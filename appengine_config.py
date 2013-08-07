# To change this template, choose Tools | Templates
# and open the template in the editor.


from ease.gaesessions import SessionMiddleware


def webapp_add_wsgi_middleware(app):
     app = SessionMiddleware(app, cookie_key="etelos develop by Mitul Golakiya")
     return app