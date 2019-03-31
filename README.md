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
order. Recently I realised that if the object dependencies are expressed 
in a graph then topological sort can be used to calculate the order the operations.
For create operations we process objects in topological order, and for drop operations we
process them in reverse topological order.

Another important insight to help with organising the code was to express 
the relationships between two objects as another object. For example, the fact that
a `Database:d` is owned by `User:u` is better expressed when behind the scenes
you introduce a separate object `DatabaseOwner:d+u`. The dependencies then are:

```yaml
Dependencies:

    - Object: User:u

    - Object: Database:d
      DependsOn:
        - User:u

    - Object: DatabaseOwner:d+u
      DependsOn:
        - Database:d
        - User:u

```

The separation of database from database ownership allows us to remove the owner of the database
before attempting to drop the database.


### Permissions Model

By default, the implicit `PUBLIC` group has access to all databases. Default privileges 
are per database, so there is no default privilege we can create to avoid this. For every newly
created database you have to revoke public group's access to the database.
  
    REVOKE ALL PRIVILEGES ON DATABASE {self.name} FROM GROUP PUBLIC
