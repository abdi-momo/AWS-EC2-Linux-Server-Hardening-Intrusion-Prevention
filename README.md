Part 1: Cloud Server Setup
1.	Selecting a Cloud Provider 
To begin the cybersecurity practicum, the first essential step was to create a cloud server using Amazon Web Services (AWS). AWS offers a Free Tier account that allows students and beginners to explore cloud computing services at no cost for 12 months (within usage limits).
2.	Creating an AWS Free Account
2.1.	 Visit the AWS Free Tier Website
•	Go to: https://aws.amazon.com/free 
•	Click on “Create a Free Account.”
2.2.	 Enter the Email and Set Up the Account
•	Enter a valid email address.
•	Choose a password and AWS account name.
•	Click Continue to proceed.
2.3.	 Choose Account Type
•	Select “Personal” as the account type.
•	Enter the name, address, and phone number.
2.4.	 Add a Payment Method
	Enter the credit or debit card details.
Note: AWS charges $1 temporarily to verify the card. This amount is refunded.
	Confirm the billing address.
2.5.	 Verify the Identity
	Enter a valid phone number.
	Choose Text Message (SMS) or Voice Call for verification.
	Enter the received verification code.
2.6.	 Select a Support Plan
	Choose the Basic (Free) support plan.
	Click “Complete Sign-Up.”
2.7.	 Log into the AWS Management Console
	Visit https://console.aws.amazon.com
	Log in with the root account credentials.
2.8.	 Launch the First EC2 Instance
After account activation, we can:
	Navigate to EC2 Dashboard (Elastic Compute Cloud).
	Click “Launch Instance” to create a virtual server.
	Choose the Amazon Linux 2 AMI (Free Tier eligible) or Ubuntu Server.

We'll use this EC2 instance throughout the practicum for setting up security measures and practicing cybersecurity skills.
2.9.	 AWS Registration Confirmation
 
Figure 1: Account Registration Confirmation
3.	Launching a Virtual Machine (VM)
3.1.	 Selecting a lightweight Linux distribution
In this practicum, we selected Ubuntu Server as our operating system for the AWS EC2 instance due to its lightweight nature, stability, and wide support in cybersecurity tools (Figure 2). During the EC2 instance launch process in the AWS Management Console, we chose an Ubuntu Server LTS (Long-Term Support) version from the list of Amazon Machine Images (AMIs), ensuring it was Free Tier eligible. This choice provided a minimal, command-line–based environment that consumes fewer resources, boots quickly, and is ideal for configuring security tools like UFW and Fail2ban while keeping the system efficient and responsive.
  
Figure 2: Selecting a lightweight Linux distribution

3.2.	 Instance Type
In this practicum, we chose the t3.micro instance type on AWS, which is part of the Free Tier–eligible options and well-suited for lightweight server tasks (Figure 3). During the EC2 launch setup, after selecting the Ubuntu AMI, we navigated to the instance type selection screen and picked t3.micro for its balance of performance and cost-efficiency. This instance provides 2 vCPUs and 1 GB of memory, which is sufficient for running basic services, firewall rules, and monitoring tools like Fail2ban without incurring extra costs, making it ideal for a cybersecurity training environment.
  
Figure 3: t3.micro instance type
3.3.	 Allocate a security group or firewall rules that allow SSH (port 22)
When launching the EC2 instance, AWS requires configuring security groups, which act as virtual firewalls controlling inbound and outbound traffic. In the setup process, we created (or modified) a security group to allow SSH access on port 22 from a trusted IP address. This step is essential to remotely connect to the server via an SSH client. By restricting inbound SSH access to only our IP address, we reduced the attack surface and prevented unauthorized login attempts. Later in the practicum, we adjusted this configuration to use a non-standard SSH port for added security.
 
Figure 4: Allocate a security group or firewall rules that allow SSH (port 22)
4.	Connection to my VM
Since we used PuTTY instead of the Linux/Mac terminal, the connection process involved using the. ppk private key file named practicum_key.ppk. First, we opened PuTTY and entered the public IP address of our AWS Ubuntu instance:
 
Next, under Connection → SSH → Auth, we browsed and selected the practicum_key.ppk file to authenticate. The username ubuntu was specified in the Session settings. After clicking Open, PuTTY established the SSH session, prompting us with a terminal login where we could securely access and manage the server.
 ![Uploading image.png…]()

Figure 5: Connection to the server via SSH.
Figure 5 show the connection to the AWS Ubuntu instance via SSH. The terminal prompt appeared as:
 
Here:
•	ubuntu → the default username for Ubuntu AWS EC2 instances.
•	ip-172-31-32-118 → the system’s hostname, which in AWS reflects the private IP address of the instance in its internal network. In this case, 172.31.32.118 is the private IP assigned by AWS inside the VPC (Virtual Private Cloud).
•	~ → indicates we are in the user’s home directory.
•	$ → shows that we are logged in as a regular (non-root) user.
This private IP is only accessible within AWS’s internal network, not from the public internet.
5.	Install Basic Server Packages
5.1.	 Update package list (if not done already)
On Ubuntu, we can update the package list and upgrade all installed packages in one command with:
 
•	sudo apt update → refreshes the list of available packages and versions.
•	&& → runs the next command only if the first one succeeds.
•	sudo apt upgrade -y → upgrades all installed packages to their latest versions, automatically confirming with -y.
5.2.	 Install Nginx
 
The -y option automatically confirms installation prompts (Refer to Figure 6).
 
Figure 6: Nginx web server Installation on Ubuntu
•	Start Nginx service
 
•	Enable Nginx to start on boot
 
Starting and enabling Nginx ensures the server runs immediately and at system boot.
•	Check if Nginx is running
 
The command above checks the current state of the Nginx service, showing whether it is active, inactive, or failed, along with recent log entries.

 
Figure 7: Nginx Status Via SSH
We can see active (running) in green in Figure 7.
•	Test our Nginx Server
In order to be able to test our Nginx Server, we must allow HTTP (port 80) inbound in our EC2 Security Group. A Security Group in AWS acts like a virtual firewall for our EC2 instance. It controls what traffic is allowed to come in (inbound) and go out (outbound) of our instance.
By default, Security Groups:
•	Block all inbound traffic (including web access on port 80)
•	Allow all outbound traffic (our server can connect out)
To do so, here are the steps to follow:
1.	Go to: https://console.aws.amazon.com/ec2
2.	In the left menu, click Instances
3.	Click our instance name to open its details
4.	Scroll down to the Security tab
•	Look for Security Groups → Click the group name
5.	In the new screen, click Inbound Rules > Edit inbound rules
6.	Add the following rule:


Field	Value
Type	HTTP
Protocol	TCP
Port	80
Source	Anywhere (0.0.0.0/0)
Table 1: Nginx Server Rules
 
Figure 8: Testing the Nginx Server

As we can see in Figure 8, after allowing all the outbound traffic, our server is running, and we can see the Nginx welcome page!
5.3.	 Setting up a simple HTML page in Nginx
To set up a simple "Hello World" HTML page on our Ubuntu Nginx server, we followed these steps — it’s fast and clean for proving the server is running.
Step-by-Step: Create a Simple HTML Page for Nginx
5.3.1.	Go to Nginx’s default web directory
Type the following command to access html directory where we’ll create the index.html file Figure 8.
 
5.3.2.	Create an index.html file
We can use either nano or vi to create/edit the file. In our case we are using nano as follow:
 
5.3.3.	Creating the simple HTML code:
 
 
Figure 9: Index.html file's content
Figure 9 shows the content of the index.html file. 
5.3.4.	Reload Nginx (optional, not always needed):
 
5.3.5.	Let’s visit our server’s public IP in our browser
 

 
Figure 10: The “Hello World” page being served.
Figure 10 shows that the HTML page we set up is running successfully and can be accessed using the public IP address: http://18.116.231.43/. 
Part 2: Server Security Configuration
1.	Change Default SSH Settings
1.1.	 Modify the default SSH configuration to:
This step involves editing the SSH server configuration file (/etc/ssh/sshd_config) to improve security. 
1.1.1.	Disable root login
Disabling root login (PermitRootLogin no) prevents direct remote access to the root account, reducing the risk of brute-force attacks.
1.1.2.	Open the SSH configuration file
Changing the default SSH port from 22 to a non-standard port like 2222 (Port 2222) helps reduce automated attack attempts by bots scanning for the default SSH port. After making these changes, the SSH service must be restarted for them to take effect.
 
1.1.3.	Find the line:
 
Uncomment it (remove the #) and change it to:
 Refer to the figure bellow: 
Figure 11: Changing the configuration file
•	Save and exit:
•	Press Ctrl + O, then Enter to save.
•	Press Ctrl + X to exit.
•	Restart the SSH service:
 
•	Test it
We try to login as root in Windows PowerShell, and here is the what it’s showing:
 
Please refer to Figure 12 bellow: 
Figure 12: Login via Windows PowerShell

This means that:
	The SSH service is reachable (no timeout anymore)
	Our key is working
	But the server is refusing login for root (Permission denied), as per our configuration
b.	Change the default SSH port from 22 to a non-standard port
Changing the default SSH port from 22 to a non-standard port like 2222 is a smart move for security by obscurity — it helps reduce automated attacks and bots scanning for port 22.
1.1.4.	Step-by-Step: Change SSH Port to 2222 on Ubuntu (EC2)
•	Important Warning First
If we do this without updating the Security Group, we will lock ourself out of the server.
So, we follow these steps exactly in order:
•	Add Port 2222 to our Security Group
1.	Go to AWS EC2 Console → Instances → Select our instance
2.	Scroll to Security > Security Groups → click the group name
3.	Click Edit Inbound Rules
4.	Add this rule:
Type	Protocol	Port	Source
Custom TCP	TCP	2222	0.0.0.0/0
Table 2: TCP Adding Rules
5.	We click Save rules
a.	Edit the SSH Configuration File
SSH into our server (still using port 22):
 
We find this line (may be commented): 
 
Change it to:
 
Restart the SSH Service :
 
Log Out and Reconnect Using Port 2222
 
 
Figure 13: Login Via SSH Using Port 2222
Running this command:
 
Shows the SSH server in not listening on port 2222.
Let’s fix this step-by-step and confirm whether SSH is configured to use port 2222.
 	Step 1: Check if Port 2222 Is Set in sshd_config
	Run:
 
	Now, look for:
 
 	Step 2: Apply the Change
Before restarting the SSH service, fix the warning we saw earlier:
 
Now run again:
 
Expected output:
 
Figure 14: Testing SSH on Port 2222
 	Step 3: Test SSH on Port 2222 (from a new PuTTY window)
	Host Name: ubuntu@18.116.231.43
	Port : 2222
	Private key: Load the .ppk file
It works as we can see in Figure 14. 
We're now using a custom SSH port.
 
Figure 15:  SSH login via the non-standard port.
1.2.	 Implement SSH key-based authentication and disable password-based logins.
To implement SSH key-based authentication and disable password logins on our Ubuntu EC2 instance for stronger security, we will follow these steps bellow:
	Confirm key-based login works (already done via PuTTY +. ppk)
	Edit the SSH config to disable password login
	Restart SSH and test
	(Optional) Enforce key-only logins for specific users
Step-by-Step Guide:
 	SSH into our instance (still using our key and current port, e.g., 2222)
	Open the SSH config file
 
	Look for these lines and edit/add/uncomment them:
 
	Save and exit
Ctrl + O → Enter (save)
Ctrl + X (exit)
	Restart SSH service
 
As w edited the port and are using ssh.socket, we use this instead:
 
 	Test in a new PuTTY window
We open PuTTY and connect using:
•	Host: ubuntu@18.116.231.43
•	Port : 2222
•	Our .ppk key under SSH > Auth
 
Figure 16: Test the Connection SSH key-based authentication without Password
 
Figure 17: Authentication failure test
Try logging in without a key (e.g., from another SSH client or wrong PuTTY profile), we are getting the above error in Figure 17. Which means permission denied.
2.	Install and Configure a Basic Firewall
Setting up a firewall like UFW (Uncomplicated Firewall) is essential to secure our Ubuntu server.
2.1.	 Step-by-Step: Install and Configure UFW on Ubuntu
2.1.1. Install UFW
 
2.1.2. Check UFW Status
 
 
Figure 18: UFW Status
From the Figure 18, we can see that it says inactive, which means that we're good to start configuration.
2.1.3. Allow Only Necessary Ports
	Allow SSH (on port 2222, since we changed it)
 
Figure 19: Allowing SSH on Port 2222
The figure above shows that we’ve successfully allowed SSH on port 2222 through the UFW firewall.
2.1.4. Enable UFW
 
When prompted:
Command may disrupt existing ssh connections. Proceed with operation (y|n)?
We press y and hit Enter.
Since we've allowed port 2222 already, our SSH access will remain.
 
2.1.5. Check Final Status
 
 
Figure 20: Final status of the UFW
Figure 20 shows us that we're now protected by a simple but effective firewall.
2.2. Set up firewall rules
2.1.1. Allow SSH traffic only on the non-standard port.
Let's now ensure that SSH is allowed only on our custom port (2222) and all other ports are blocked by default (which we already did earlier with ufw default deny incoming).
 
That message just means the rule to allow SSH on port 2222 is already in place — so we're good!
2.2.2. Remove access to the default SSH port (22) if it was ever added:
 
As no rule exists for port 22, it’s saying “Could not delete non-existent rule” — which’s fine.
2.3.	Allow HTTP traffic (port 80) and/or HTTPS traffic (port 443) for the web server.
2.3.1. Allow HTTP traffic (port 80)
The bellow figure shows that we've now allowed HTTP (port 80) through UFW — our server is now accessible for regular web traffic.
 
2.3.2. Allow HTTPS traffic (port 443)
The Figure 21 shows that we’ve now allowed HTTPS traffic (port 443) through our firewall, which is great if we plan to serve secure (SSL/TLS) web content in the future.
 
2.3.3. Check current firewall rules
 
 
Figure 21: HTTP & HTTPS Traffic status
Summary
Port	Purpose	Status
2222	SSH	Allowed
22	SSH	Blocked
80	HTTP	Allowed
443	HTTPS	Allowed
All others	--	Blocked by default
Table 3: Firewall rules status
 2.3.4. Deny all other inbound traffic.
UFW does this by default, but to be sure:
 
 
Figure 22: Locking down all other inbound traffic
From Figure 22, we can notice that we’ve now locked down our server using a default-deny inbound policy, which is a core principle of firewall security.
Let’s interpret the Figure 22’s content:
Direction	Default Action	Meaning
Incoming	Deny	All traffic is blocked unless explicitly allowed (great for security)
Outgoing	Allow	Our server can still reach the internet, install packages, etc.
Table 4: Figure 22's interpretation
 
 
Figure 23: Inbound traffic blocked
That satisfies: “Deny all other inbound traffic.” in Figure 23.
3.	Install and Configure Fail2Ban
Installing Fail2Ban is a great way to automatically detect and block malicious IPs trying to brute-force our SSH (or other services).
3.1.	 Install and Configure Fail2Ban for SSH
 
3.1.1. Enable and start the Fail2Ban service
 
 
Figure 24: Enabling Fail2Ban.
Fail2Ban is now installed, enabled, and running on our server as it’s shown in Figure 24. 
3.1.2. Create a Local Config File
Instead of editing the default config directly, copy it to a local override file:
 
Then open it:
 
3.1.3. Find and edit the [sshd] section
Scroll down to find and set the following (or ensure they are uncommented and configured):
 
Setting	Meaning
Port	Use our SSH port (e.g., 2222)
bantime	Ban duration in seconds (e.g., 600 = 10 min)
findtime	Time window to track failures (in sec)
maxretry	Failures allowed before ban
Table 5: Editing the sshd section
3.1.4. Restart Fail2Ban
 
3.1.5. Check Fail2Ban status
 
 
Figure 25: Checking the Fail2Ban status.
Fail2Ban is now running and monitoring SSH on port 2222 as it is shown in Figure 25.
	fail2ban-client status confirms 1 active jail: sshd
	Fail2Ban is now protecting our server from malicious SSH attempts.
3.1.6. Next Recommendations (Optional but Good Practice)
•	Check jail-specific status:
 
 
Figure 26: Logs from Fail2Ban banning an IP status
This shows banned IPs, attempt logs, etc.
Everything looks great! Our sshd jail is active and correctly configured.
•	Breakdown of the Output:
•	Currently failed: 0 → No recent failed login attempts.
•	Total failed: 0 → No failed attempts recorded yet (we’re safe so far).
•	Currently banned: 0 → No IPs currently blocked.
•	Total banned: 0 → No IPs have been banned yet.

•	Enable Fail2Ban on boot (if not already):
 
Fail2Ban has been successfully enabled to start at boot!
This means that even after a server restart, Fail2Ban will:
•	Automatically launch
•	Monitor our log files (e.g., for SSH brute-force attempts)
•	Enforce our banning rules without needing manual intervention
3.1.7.	Regularly check logs
 
 
Figure 27: Regularly check logs
From the journalctl logs, we can now confirm that fail2ban started successfully at the end. The previous errors (option 'backend' in section> or section 'sshd' already exists) were due to syntax/config issues in jail.local, but they are now resolved.
What’s Working Now:
•	fail2ban.service is enabled
•	sshd jail is active
•	Fail2Ban is running without errors
•	It's protecting SSH on our custom port (e.g., 2222)
3.2.	Configure fail2ban to ban IPs after 3 failed login attempts.
To configure Fail2Ban to ban IPs after 3 failed login attempts, follow these steps:
3.2.1.	Edit the jail.local file
Open our jail configuration file:
 
We modify the parameter of maxretry: Bans after 3 failed login attempts
 
Figure 28: Configuring the Fail2Ban to ban IPs after 3 failed login attempts
•	maxretry = 3 → Bans after 3 failed login attempts
•	bantime = 600 → Ban duration in seconds (10 minutes)
•	findtime = 600 → Time window to count failures (10 minutes)

3.2.2.	Restart Fail2Ban
 
3.2.3.	Confirm the Jail is Active
 
 
Figure 29: Jail confirmation status
•	Currently failed = 0
•	Total failed = 0
•	Jail name = sshd
These mean that Jail is Active
4.	Monitoring & Logging:
4.1.	Enable basic logging
4.1.1.	Enable basic logging for SSH
SSH logging is typically enabled by default on Ubuntu via sshd and rsyslog. But to ensure it's working correctly, do the following:
4.1.2.	Ensure SSHD logs to /var/log/auth.log
Open the SSH daemon config:
 
Verify or add the following line (usually enabled by default):
 
INFO is sufficient for basic login events (accepted/failed logins, disconnected sessions).
We can also use VERBOSE for more detailed logs (like attempted usernames).
4.1.3.	After saving the file, restart SSH:
 
4.1.4.	Ensure rsyslog is running
SSH log entries are sent to /var/log/auth.log via rsyslog. Check if it's enabled:
 
 
Figure 30: Rsyslog status
4.1.5.	Verify SSH login logs
We now see login attempts in:
  We now see login attempts in:
	The log contains events such as:
 
Figure 31: Log's content
	Authentication method errors and disconnections
 
Figure 32: Authentication method
	Session opened and closed
pam_unix(sshd:session): session opened for user ubuntu
pam_unix(sshd:session): session closed for user ubuntu
 
Basic logging for SSH is enabled by default through rsyslog and OpenSSH. On Ubuntu systems, SSH authentication logs are written to /var/log/auth.log. This was verified by inspecting the log file, which includes SSH connection attempts, authentication methods, session start/stop messages, and invalid login attempts.
4.1.6.	Enable basic logging for firewall activity
To enable basic logging for firewall activity on Ubuntu (assuming you're using ufw as the firewall), we follow these steps:
•	Enable UFW Logging
 
 
Figure 33: Enable basic logging for firewall activity
This sets the logging level to the default (low), which logs blocked incoming connections.
•	Check Current Logging Level (Optional)
 
 
Figure 34: Logging Level
Look for: Logging: on (low)
We can choose from the following levels:
	off
	low (default – logs blocked incoming)
	medium (logs some allowed connections)
	high (logs most events)
	full (logs all events)
To increase the verbosity:
 
•	Check Current Logging Level
 
Figure 35: Current Logging Level
4.1.7.	View Firewall Logs
Logs are stored in:
 
We can view them with:
 
Or follow them in real-time:
 
We enabled basic firewall logging by running sudo ufw logging on. This allows the system to log blocked incoming connection attempts. Logs can be reviewed in /var/log/ufw.log using less or tail -f. This helps in monitoring and auditing firewall activity.
4.2.	Use a simple log monitoring tool like logwatch to summarize and review server activity.
To summarize and review server activity using a simple log monitoring tool like Logwatch, follow these steps:
4.2.1.	Install Logwatch
 
4.2.2.	Run Logwatch Manually
To get a summary report of the current day's activity:
 
Or, if we just want to see the report in the terminal:
 
We can also run for specific services, like:
 
4.2.3. Optional – Configure Daily Email Reports
Edit the default config file:
 
Update these lines:
 
 
Conclusion – Cybersecurity Practicum at JTG Systems (AWS-Based)
My cybersecurity practicum with JTG Systems, hosted on an AWS EC2 server, provided me with a hands-on, real-world environment to apply and deepen my theoretical knowledge from ABM College.
Throughout this experience, I:
	Secured SSH access by configuring Fail2Ban, implementing login attempt limitations, and changing default SSH ports to prevent brute-force attacks.
	Monitored system and firewall logs, including enabling and inspecting /var/log/auth.log for SSH activity and /var/log/ufw.log for firewall events.
	Installed and configured logwatch, a lightweight log monitoring tool, to automatically summarize and review system activity—ensuring continuous monitoring and reporting.
	Learned how to interpret logs, troubleshoot permission issues, and handle service-level errors related to misconfiguration or conflicting entries.
	Gained familiarity with systemd, rsyslog, and basic intrusion prevention, essential for maintaining server integrity in production environments.
	Practiced real-time incident response techniques and system hardening measures using industry tools and open-source configurations.
This practicum has significantly enhanced my understanding of cybersecurity practices in cloud environments, especially on Linux-based servers hosted on Amazon Web Services. It has bridged the gap between classroom learning and professional security operations, preparing me for roles that demand practical security implementation skills in live systems.
I now feel more confident and capable of contributing to real-world cybersecurity tasks—whether in entry-level SOC roles, system administration, or future DevSecOps pathways.
