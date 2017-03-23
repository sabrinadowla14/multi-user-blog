import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# random string use as our hash secret for cookies.

secret = 'sdowla'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Functions for taking one of those secure values and making sure it's valid.


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# BlogHandler class -- here we have all the generic stuff that all the handlers
# can use


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# sets a cookie whose name is name and value is val

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

# give it a name, and if finds that cookie in the request if
# cookie_val and pass check_secure_val then return cookie val.

    def read_secure_cookie(self, name):
        # find the cookie in the request
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        # This function sets a secure cookie, user ID, and it equals to the
        # users ID. Gets the user's id and data store.
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


# Reads the cookie and makes sure that cookie is valid and
# sets the user on the handler.
# Check if user is logged in or not.

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        # if user_id is valid it assigns self.user to that user
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# make user information secure


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# h is what we store in the db
# returns salt and hash version of name, pw and salt


def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# takes name, password and h from the database
# and checks if h from the database matches
# users version of hasvalue.


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# users_key creates the ancestor element in the database to
# store all of our users.


def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# users object we will be storing in the database.


class User(db.Model):
    name = db.StringProperty(required = True)
    # store the hash of the password
    pw_hash = db.StringProperty(required = True)
    # email is not required.
    email = db.StringProperty()

    # looks up a user by id
    # you can call this method[by_id] on this object[User]
    # user.byid give it an ID, get_by_id to load the user on to the
    # database doesn't have to be an instance of the object
    # cls refers to self, which here is Class User

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

# looks up a user by name cls refer to class User

    @classmethod
    def by_name(cls, name):
        # select all from user where name == name, .get() returns the
        # first instance
        u = User.all().filter('name =', name).get()
        return u

    # takes name, pw and email and creates a new User object
    # creates a new User object, but doesn't store in DB

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

# going to call user class functions by_name method. We say class by name
# not user by name so that we can over write this function.by name looks
# for a user of that neme. if it exist it's a valid password.

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def userName(self):
        user = User.by_id(self.user_id)
        return user.name     

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)


class BlogFront(BlogHandler):
    def get(self):
        # renders all posts, sorted by date
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)        


class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def userName(self):
        user = User.by_id(self.user_id)
        return user.name
        
        
class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def userName(self):
        user = User.by_id(self.user_id)
        return user.name
        
# renders post, like counts, comments and errors


class PostPage(BlogHandler):
    def get(self, post_id):
        """
            This renders home post page with content, comments and likes.
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        if not post:
            self.error(404)
            return

        error = self.request.get('error')

        self.render("permalink.html", post=post, likeCount=likes.count(),
                    comments=comments, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        c = ""
        if(self.user):
            # post-like value increases by clicking like.            
            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))

                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=You cannot like your own " +
                                  "post.!!")
                    return
                elif likes.count() == 0:
                    like = Like(
                            parent=blog_key(),
                            user_id=self.user.key().id(),
                            post_id=int(post_id))
                    like.put()
                    
            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("/login?error=First login and then " +
                          "try to edit, comment or like.!!")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post,
                    comments=comments, likeCount=likes.count(),
                    new=c)


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            com = db.get(key)
            if com.user_id == self.user.key().id():
                com.delete()
                self.redirect("/blog/"+post_id+"?delCommentId=" +
                              comment_id)
            else:
                self.redirect(
                        "/blog/" + post_id + "?error=You" +
                        "cannot delete this comment.")
        else:
            self.redirect("/login?error=First login and then delete!! ")
                                

class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            com = db.get(key)
            if com.user_id == self.user.key().id():
                self.render("editcomment.html", comment=com.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You cannot edit this " +
                              "comment.")
        else:
            self.redirect(
                   "/login?error=If you want" +
                   "to edit this comment, login first!")

    def post(self, post_id, comment_id):
        """
            Updates post.
        """
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            com = db.get(key)
            com.comment = comment
            com.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editcomment.html", subject=subject,
                        content=content, error=error)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(
                    parent = blog_key(), user_id=self.user.key().id(),
                    subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                   "newpost.html",
                   subject=subject,
                   content=content,
                   error=error)
            

class UpdatePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            
            if post.user_id == self.user.key().id():
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
            
                error = ""
                self.render(
                         "updatepost.html", subject=post.subject,
                         content=post.content,
                         error=error, post = post)
            else:
                self.redirect("/errormsgdelete")
                
    def post(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)
            p.subject = self.request.get('subject')
            p.content = self.request.get('content')
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
            
               
class DeletePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
                       
            if post:
                post.delete()
                self.render(
                        "deletepost.html", post = post,
                        post_id = post_id,
                        username = self.user.name)
            else:
                self.redirect("/errormsgdelete")


class ErrorMsgDelete(BlogHandler):
    def get(self):
        msg = 'You can only edit or delete posts you have created.'
        self.render('errormsgdelete.html', error = msg)
        
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
            
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
            
        # if we have an error we re-render the form with the error
        # messages and values.
        
        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
            
    # just raises an error
    
    def done(self, *a, **kw):
        raise NotImplementedError


# inherits from the Signup class

class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        # if user exist then send error message.
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            # call the login function, which set the cookies.
            self.login(u)
            self.redirect('/blog/welcome')            
# This is a login page, not for creating a new user, but signing into an
# old one.


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        # out of the request we get the username and password.
        username = self.request.get('username')
        password = self.request.get('password')

        # we call the login function on the user objects. It returns
        # the user if username and passwords are valid. It returns
        # none if it's not.
        # it will sets the cookie
        
        u = User.login(username, password)
      
        if u:
            # login function here on the blog handler.
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login, you need to signup first!!'
            self.render('login-form.html', error = msg)


class Logout(BlogHandler):
    def get(self):
        # call the logout function which is in Bloghandler class
        self.logout()
        self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', Login),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/updatepost/([0-9]+)', UpdatePost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/([0-9]+)/([0-9]+)/deletecomment',
                                DeleteComment),
                               ('/blog/([0-9]+)/([0-9]+)/editcomment',
                                EditComment),
                               ('/errormsgdelete', ErrorMsgDelete),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ],
                              debug=True)
