# P3-Item-Catalog

An application that provides a list of products within a variety of catalogs as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

1. download all Files keeping folders in tact
    
    Note: app uses Python 2.7 with imported libraries from Flask 0.10 web framework, SQLAlchemy 0.9 and Oauth2

2. database_setup.py will create your initial blank database

3. application.py will allow you to interact with your database on localhost:8000

4. load localhost:8000/catalog/ in web browser and browse through app
    
    Note: JSON GET requests are available at...

          /catalog/JSON - provides a serialized list of catalogs
      
          /catalog/<int:catalog_id>/product/JSON - provides a serialized list of products for specified catalog id
      
          /catalog/<int:catalog_id>/product/<int:product_id>/JSON - provides a serialized specified product from specified catalog using catalog and product ids

5. if not logged in with facebook or google+ all information will be read only

6. once logged in user will be able to add new catalogs and edit or delete catalogs created by them

7. once catalogs are created users will be able to add, edit and delete products associated to catalogs they created
