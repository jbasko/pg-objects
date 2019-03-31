# pg-objects

I have been trying to express PostgreSQL and Redshift permission objects declaratively 
for the last year and a half. This is roughly what I am after: 

```yaml
Objects:
    - Type: User
      Name: u
    - Type: Database
      Name: d
      Owner: u
```

The greatest challenge so far has been to create and drop all the objects in the right
order. Yesterday (2019-03-30) I realised that if I express all the object dependencies 
in a graph then I can use topological sort and order the operations based on that.
For create operations we process objects in topological order, and for drop operations we
process them in reverse topological order.

Another important insight to help with organising the code was to express 
the relationships between two objects as another object. For example, the fact that
a database `d` is owned by user `u` is better expressed when behind the scenes
you introduce a separate object called database owner.

Intuitive dependency graph (**not a good idea**):

```yaml
DependencyGraph:
    - Object: User:u
    - Object: Database:d
      DependsOn:
        - User:u
```

Done this way, you have a database resource that is created with:

```sql
CREATE DATABASE d OWNER u
```

and dropped with:

```sql
DROP DATABASE d
```

So, you'd think you could write clean `create` and `drop` methods for each resource type,
but **this idea explodes** when you want to drop user `u`.

Why? Because `User:u` does not depend on `Database:d` yet it cannot be dropped until you
reassign the ownership of `Database:d` to someone else. Now you have to introduce hacks 
in the `drop` method of `User` and the code becomes very specific to the type of objects 
you are working with.

A better dependency graph can be constructed if we introduce the new object type `DatabaseOwner`
and make an instance of it depend on `Database` and `User`:

```yaml
Objects:
    - Type: User
      Name: u
    - Type: Database
      Name: d
      Owner: u

ImplicitObjects:
    - Type: DatabaseOwner
      Name: d+u
      Database: d
      Owner: u

DependencyGraph:
    - Object: User:u
    - Object: Database:d
    - Object: DatabaseOwner:d+u
      DependsOn:
        - Database:d
        - User:u
```

Now you can have nice methods to create and drop users, create and drop databases, and *create*
and *drop* database owners. All the logic of reassigning `DatabaseOwner` can go into the dedicated
`DatabaseOwner` class and `User` should not worry about it.

`ImplicitObjects` don't need to be declared by programmer, they are created behind the scenes based
on `Objects`. When user decides to drop `User:u`, they will change `Owner:` property to something
else and a new implicit `DatabaseOwner` will be created. For `DatabaseOwner` the create method
would actually execute `ALTER DATABASE OWNER TO ...`. Since create statements are applied first,
there is nothing to be done in the drop method of `DatabaseOwner` - the owner will have been
implicitly deleted, and since it depends on `User:u`, it will have been deleted before we get to
user deletion which means that user deletion will succeed.
