# Moodle External Webservice Authentication Plugin

Moodle plugin to authenticate users against external webservice.

This plugin let you configure a SOAP webservice
to authenticate users against it.

Install
-------

* Put these files at moodle/auth/ws/
 * You may use composer
* Log in your Moodle as Admin and go to "Notifications" page
* Follow the instructions to install the plugin

Usage
-----

You configure the web service URL, the name of the function to be called, the returned Class and attribute to get the boolean result from.

This plugins does not create users, and also does not update users records.

Users are suposed to be created and updated by external service using the Moodle's webservices.

Users should have "auth = ws" for this plugin to authenticate users.



