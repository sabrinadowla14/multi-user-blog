Project: Multi User Blog


Documentation of my Project:


This project is my first project in my Nanodegree where I have designed a blog.
The two main technologies used in this project are Google App Engine and Jinja.

Setup

Installed Python 2.7.
Install Google App Engine SDK.
Signed Up for a Google App Engine Account.
Deployed my project with gcloud app deploy.
Viewed my project at multi-user-name.appspot.com.
When developing locally, I could use dev_appserver.py to run a copy of my app on my own computer,
and access it at http://localhost:8080/.
Installed Jinja and created helper functions for using Jinja.

Steps:

Step 1: Created a Basic Blog
It has Front page that lists blog posts.
A form to submit new entries.
Blog posts have their own page

Step 2: Added User Registration
Have a registration form that validates user input, and displays the error(s) when necessary.
After a successful registration, a user is directed to a welcome page with a greeting,
“Welcome, [User]” where [User] is a name set in a cookie. If a user attempts to visit 
the welcome page without being signed in (without having a cookie), then redirect to the Signup page.
passwords where stored securely.

Step 3: Added Login
Have a login form that validates user input, and displays the error(s) when necessary.
After a successful login, the user is directed to the same welcome page from Step 2.

Step 4: Added Logout
Have a logout form that validates user input, and displays the error(s) when necessary.
After logging out, the cookie is cleared and user is redirected to the Signup page from Step 2.

Step 5: Added Other Features.
Users can only be able to edit/delete their posts. They receive an error message if they disobey this rule.
Users can like/unlike posts, but not their own. They receive an error message if they disobey this rule.
Users can comment on posts. They can only edit/delete their own posts, and they should receive an error
message if they disobey this rule.

How to Run a project:
Go to google App Engine Launcher.
Go to file and add existing Application.
Select that file in google App Engine.
Run it
Open it in the browser.

Checked my code using Pep8 and also autopep8

