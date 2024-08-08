# PasswordManager
a terminal based password manager with encryption.

## usage
the app is used in a manner much similar to the metasploit-framework. upon launch the user is thrown into a shell-like prompt in which different unix-like commands may be typed.

it requires users create user accounts under which records may be saved, modified, etc. commands differ based on whether a user is logged in or not. password related tables include fields for storing the username, password and website.  

the database can be configured via the config file (%filepath%/cfg/config). by default the database is set to be in the same directory as the path to the file (referenced in the cfg file by path=%file%). the databases name by default is default.db (as seen in the config file). the program will always look for an adjacent directory named 'cfg', and for a file inside of it named 'config'. the program will throw an error and not work if this file is not present

## ciphers/security
the program uses a 64 byte (512 bit) feistel cipher with rotating intermediary swap operations. it iterates over itself 16 times, and uses cyptographically related hash values as keys with each iteration. a special syntax may be used to specify swapping operations (specified in the class definitions). no content, decryption keys, or passwords are stored directly as plaintext and all encrypted values are salted before being stored.

while this all probably sounds good, it does not imply it is a secure or optimal implementation of the algorithm, or that it should actually be used for security.

## syntax
many commands allow for both prompt based input or argument based input. indexes may also be specified in certain contexts.

## when logged out
<ul>
  <li><b>new</b> -- shows user set of prompts to set up a new master user account</li>
  <li><b>update &lt;index&gt; &lt;field or field index&gt; <em>**if field is not password</em> &lt;value&gt;</b> -- update an existing master user or master user's password.</li>
  <li><b>rm &lt;user or uid&gt;</b>-- removes a specific user</li>
  <li><b>login &lt;username or index&gt;></b>-- logs in as specific user. may also be used followed by a name or index (relative to the output of the users command)</li>
  <li><b>users</b> -- lists all created users</li>
  <li><b>whoami</b> -- will always return "not logged in" in this context</li>
</ul>

## when logged in
<ul>
  <li><b>logout</b> -- logs out the master user that is currently logged in </li>
  <li><b>whoami</b>-- returns the name of the current master user</li>
  <li><b>ls</b> -- when provided with no arguments lists all records. when run with -u <filter> will filter by username, and -s <filter> to filter by site (regex not supported)</li>
  <li><b>update &lt;index&gt; &lt;field&gt;=&lt;value&gt;</b> -- updates a username, site, or password of a specific record by index </li>
</ul>
    
## global commands
<ul>
  <li><b>backup &lt;path&gt;</b> -- makes backup copy of current database at path &lt;path&gt;</li>
  <li><b>clear</b> or <b>clc</b> -- clears screen</li>
  <li><b>exit</b> -- in most contexts, one should be able to exit by simply typing exit.</li>
  <li><b>help</b> -- brings up help menu</li>
</ul>


