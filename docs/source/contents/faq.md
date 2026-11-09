FAQ
===

**Why can't SAML be implemented as an Django Authentication Backend?**

well SAML authentication is not that simple as a set of credentials you can
put on a login form and get a response back. Actually the user password is
not given to the service provider at all. This is by design. You have to
delegate the task of authentication to the IdP and then get an asynchronous
response from it.

Given said that, djangosaml2 does use a Django Authentication Backend to
transform the SAML assertion about the user into a Django user object.

**Why not put everything in a Django middleware class and make our lifes
easier?**

Yes, that was an option I did evaluate but at the end the current design
won. In my opinion putting this logic into a middleware has the advantage
of making it easier to configure but has a couple of disadvantages: first,
the middleware would need to check if the request path is one of the
SAML endpoints for every request. Second, it would be too magical and in
case of a problem, much harder to debug.

**Why not call this package django-saml as many other Django applications?**

Following that pattern then I should import the application with
import saml but unfortunately that module name is already used in pysaml2.

**saml2.response.UnsolicitedResponse: Unsolicited response**

An unsolicited response usually means the SAML session cookie was not sent with the HTTP-POST binding. Configure the SameSite middleware described in the setup documentation, and set ``SESSION_COOKIE_SECURE = True`` so the browser accepts ``SameSite=None``.
