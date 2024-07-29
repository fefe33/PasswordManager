## PasswordManager
a terminal based password manager with simple "encryption"

## usage
the app is used in a manner much similar to the metasploit-framework. upon launch the user is thrown into a shell-like prompt in which different unix-like commands may be typed.

# application structure
the application requires users create user accounts under which records may be saved, modified, etc. commands differ based on whether a user is logged in or not. password related tables include fields for storing the username, password and website.  

# IMPORTANT NOTE
the algorithm for encryption isnt (as far as I know) secure by any means. but i wrote the class with modifyiablity in mind so that ideally one could write or import a library containing a more secure cypher and still make it work with relative ease. as far as i know, it should work with most symmetric encryption algorithms (so long as it takes a 256 bit or less key).

## syntax
many commands allow for both prompt based input or argument based input. indexes may also be specified in certain contexts.
# when logged out
<ul>
  <li>new -- shows user set of prompts to set up a new master user account</li>
  <li>update &lt;index&gt; &lt;field or field index&gt; **if field is not password &lt;value&gt;-- update an existing master user or master user's password. a value may not be repeated</li>
  <li>rm -- removes a specific user</li>
  <li>login &lt;username or index&gt;>-- logs in as specific user. may also be used followed by a name or index (relative to the output of the users command)</li>
  <li>users -- lists all created users</li>
  <li>whoami -- will always return "not logged in" in this context</li>
</ul>
# when logged in
<ul>
  <li>logout -- logs out the master user that is currently logged in </li>
  <li>whoami -- returns the name of the current master user</li>
  <li>ls -- when provided with no arguments lists all records. when run with -u <filter> will filter by username, and -s <filter> to filter by site (regex not supported)</li>
  <li>update <index> </li>
</ul>
# global commands
<ul>
  <li>clear or clc -- clears screen</li>
  <li>exit -- in most contexts, one should be able to exit by simply typing exit.</li>
  <li>(not implimented) help -- brings up help menu</li>
</ul>
