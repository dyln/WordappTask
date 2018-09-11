# WordappTask

# Task Definition
I want to build a mobile app that people can use so as to create blog posts and review comments regarding to posts. So my mobile app needs a rest API server to manage all stuff. 

# Functional Requirements:
I want to be able to sign up by email/password or Facebook;
I want to be able to sign in using access token (Oauth Authentication)
I want to be able to create/update/delete posts;
I want to be able to attach files to posts
I want to be able to mark post as 'draft' (not public)
I want to be able to mark post as 'publish' (public)
I want to be able to read/update/delete comments
I want to be able to mark comment as 'visible' (public)
I want to be able to mark comment as 'invisible' (not public)

# Technical Requirements
It should be a WEB application:
For the server side you would use any technology that runs on Ubuntu server.
It should have server side validation;
It should have a user authentication solution. The user should only have access to his/her own posts and comments
It should have automated tests for all functionality (models, controllers, acceptance/functional tests);
The rest API server should have versioning.
Use GIT as a version control
Use SQLITE as database server

# Installation & Documentation
Your API server should run on any Ubuntu Server. 
Your API server should not have complex dependency.
You should write clean documentation for installing the app and make it run.
