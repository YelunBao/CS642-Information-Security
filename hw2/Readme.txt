Attack A: Cookie Theft

Use the hint given in the homework, and replace the content in <script> tag. Fill it with Email script, and let the payload be the cookie(which can be get by document.cookie.). Then we only need to redirect to user.php using "window.location"


Attack B: Cross-Site Request Forgery

Use hidden frame. Use the same form in http://zoobar.org/transfer.php, which is in <form>. Imitate the 3 <input> tags. Then in <script>, use .click() to simulate click operation, and setTimeout() to avoid being too fast redirecting.


Attack C: SQL Injection

Use the same login form in http://zoobar.org/index.php. Imitate the 3 <input> tags of username, password and login, but make password input hidden. Define a function in <script> and let this function control submission. Append "'--" to the username to ignore rest of line, and return true by default.