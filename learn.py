"""Learn tab lessons (2026-11-19). Content only; web.py renders it. body is trusted static HTML."""
LESSONS = [
    {"id": "siem-basics", "title": "What a SIEM does", "minutes": 4, "body": """<p>A SIEM (security information and event management system) is the place where a security team reads everything that happened, in one format, with the important parts pulled to the top. Every SIEM does the same five jobs. Watchtower does all five, and you can point at the part of it that does each one.</p>

<h3>1. Collect</h3>
<p>Logs live in many places: AWS, your PC, your tailnet. A SIEM goes and gets them on a schedule. In Watchtower each source has its own collector in <code>collectors/</code>:</p>
<ul>
<li><b>cloudtrail</b>: AWS management events (who called which AWS API), every 5 minutes.</li>
<li><b>posture</b>: a snapshot of the AWS account's security settings (MFA, access keys, open security groups, trails), every 6 hours.</li>
<li><b>windows</b>: this PC's event logs (Security, System, Defender, PowerShell, Firewall), every 5 minutes.</li>
<li><b>tailscale</b>: devices on the tailnet, new or going online and offline, every 2 minutes.</li>
<li><b>s3logs</b>: CloudTrail files and VPC flow logs from the log bucket, every 15 minutes.</li>
</ul>
<p>Each collector also records its own health, which you see in the Collectors table on the <a href="/">Overview</a>.</p>

<h3>2. Normalize</h3>
<p>A CloudTrail record and a Windows event look nothing alike. If every rule had to understand every format, you would write each rule five times. So <code>normalize.py</code> turns every record into one shape: <code>ts</code>, <code>source</code>, <code>action</code>, <code>outcome</code>, <code>actor</code>, <code>src_ip</code>, <code>target</code>, <code>region</code>, plus an <code>extra</code> dict and the original <code>raw_json</code>. That is why one search box on <a href="/events">Log activity</a> works across every source.</p>

<h3>3. Correlate</h3>
<p>A rule looks for a pattern in those events. One matching event is a <b>hit</b>. Hits for the same rule and the same <b>entity</b> (a user, an address, a device) are grouped into one <b>offense</b>, so ten failed sign-ins become one thing to read, not ten. The rules are in <code>rules/builtin.py</code> and the grouping happens in <code>engine.py</code>. On top of that, when one entity trips two or more different rules within a day, the engine opens a correlation offense ("One entity tripped several rules"), because that is usually one story.</p>

<h3>4. Alert</h3>
<p>Not every offense deserves your phone buzzing. Each offense gets a <b>magnitude</b> from 1 to 10, and only new offenses at magnitude 7 or more post to Discord. Magnitude 9 or more also mentions you so it gets past a muted channel. Once a day there is a morning summary: what opened, what closed, what is still open, and whether every feed is delivering. The messages carry a title, an entity and a link, never raw logs.</p>

<h3>5. Respond</h3>
<p>This is the human part, and it is your job. You open the offense, read why it fired, look at the events, decide what happened, and close it with a verdict and a note. Your closed offenses build up in your <a href="/analyst">analyst log</a>, which is the record of your work as an analyst.</p>

<p>Keep this map in your head: <b>collectors</b> &rarr; <b>normalize.py</b> &rarr; <b>rules and engine</b> &rarr; <b>Discord pings</b> &rarr; <b>you</b>. When something looks wrong, ask which step it went wrong at.</p>""",
     "try": [("Open the Overview and find the Collectors table", "/"),
             ("Search every source at once", "/events?q=ConsoleLogin&range=7d"),
             ("See the rules that turn events into offenses", "/rules")],
     "check": [("What is the difference between a hit and an offense?",
                "A hit is one event that matched a rule. An offense groups the hits for one rule and one entity (a user, address or device) so you read them as one thing."),
               ("Why does Watchtower normalize every record into one shape?",
                "So one rule and one search work across every source. Without it you would need a separate rule for each log format."),
               ("Which offenses ping Discord?",
                "New offenses at magnitude 7 or more. Magnitude 9 or more also mentions you. Drills never ping.")]},

    {"id": "triage-loop", "title": "The triage loop", "minutes": 5, "body": """<p>Triage means deciding, quickly and with evidence, whether an alert is a real problem. Good analysts do it the same way every time, so they do not skip a step when they are tired. Here is the loop.</p>

<h3>1. Read the "why"</h3>
<p>Open the offense. The panel <b>Why this rule fired</b> tells you in one sentence what the rule was looking for. Next to it are the threshold, the source and the MITRE ATT&amp;CK technique. Before you look at any data, you should know what the rule thinks happened.</p>

<h3>2. Open the events</h3>
<p>Scroll to <b>Events in this offense</b> and select a row to read the raw log. Do not judge from the title alone. The title says what matched; the raw log says what actually happened.</p>

<h3>3. Answer five questions</h3>
<ul>
<li><b>Who?</b> Which user, role or key did it? (<code>actor</code>, and in AWS the <code>userIdentity</code> block.)</li>
<li><b>What?</b> Which action, on which thing, and did it succeed? (<code>action</code>, <code>target</code>, <code>outcome</code>.)</li>
<li><b>From where?</b> Which address, country, device or browser? (<code>src_ip</code>, country, user agent.)</li>
<li><b>When?</b> What time, and was it one event or a burst? Is the time odd for this person?</li>
<li><b>Is this normal for them?</b> Search the same actor over the last 7 days on <a href="/events?range=7d">Log activity</a>. Have they done this before, from here, at this hour?</li>
</ul>

<h3>4. Decide a verdict</h3>
<ul>
<li><b>true-positive</b>: the rule caught what it was built to catch, and it is a real problem.</li>
<li><b>false-positive</b>: the rule matched, but what it thinks happened did not happen. The rule needs tuning.</li>
<li><b>benign</b>: it really happened, and it is not harmful. You signed in from a hotel, you changed an IAM policy on purpose.</li>
</ul>
<p>The difference between false-positive and benign matters. A false-positive is a rule problem. Benign is a correct alert about a harmless thing. Counting them separately tells you which rules need work.</p>

<h3>5. Act</h3>
<p>For a true-positive, contain first: disable the key, remove the user, close the port, rotate the password. Watchtower is read-only, so you make the fix in AWS or Windows yourself, then come back.</p>

<h3>6. Write the note</h3>
<p>Write it for a stranger who reads it in six months. It should let them check your work without redoing it. Copy this:</p>
<pre>Verdict: benign
Who: alex (IAM user)
What: ConsoleLogin, success, MFA used
From: 203.0.113.25, new country (Portugal), usual browser
When: 2026-11-10 14:02 UTC, one event
Normal? First sign-in from this country. Confirmed alex is travelling (asked directly).
Action: none. Will watch for activity from this country after alex returns.</pre>

<p>Your closed offenses, verdicts and notes all show in your <a href="/analyst">analyst log</a>, along with your mean time to close. Speed matters, but a fast close with no evidence is worse than a slow one with a good note.</p>""",
     "try": [("Pick the highest open offense and run the loop", "/offenses"),
             ("Practice on a fake attack", "/drills"),
             ("Read your past notes", "/analyst")],
     "check": [("You signed in from a hotel and the new-country rule fired. Which verdict?",
                "Benign. The sign-in really happened and the rule worked as designed, but the activity was harmless."),
               ("What makes a verdict false-positive instead of benign?",
                "A false-positive means what the rule thinks happened did not actually happen, so the rule is wrong and needs tuning. Benign means it happened but was harmless."),
               ("Why read the raw log instead of trusting the offense title?",
                "The title only says which rule matched. The raw log shows who, from where, whether it succeeded, and details the rule never looked at.")]},

    {"id": "cloudtrail-event", "title": "Reading a CloudTrail event", "minutes": 5, "body": """<p>CloudTrail records every call made to the AWS API: every console sign-in, every IAM change, every security group edit. Most cloud investigations come down to reading these records well. Here is a made-up console sign-in, close to what you will see.</p>

<pre>{
  "eventTime": "2026-11-10T14:02:31Z",
  "eventSource": "signin.amazonaws.com",
  "eventName": "ConsoleLogin",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.25",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alex",
    "arn": "arn:aws:iam::111122223333:user/alex",
    "accountId": "111122223333"
  },
  "responseElements": {"ConsoleLogin": "Success"},
  "additionalEventData": {"MFAUsed": "No"},
  "readOnly": false,
  "eventType": "AwsConsoleSignIn"
}</pre>

<h3>The fields that matter</h3>
<ul>
<li><b>eventName</b>: what was done. <code>ConsoleLogin</code>, <code>CreateAccessKey</code>, <code>StopLogging</code>. Watchtower stores it as <code>action</code>.</li>
<li><b>userIdentity.type</b>: what kind of identity. <code>IAMUser</code> is a long-lived user, <code>AssumedRole</code> is a short-lived role session (SSO sign-ins look like this), <code>Root</code> is the account owner and should almost never appear.</li>
<li><b>userIdentity.userName</b> and <b>arn</b>: exactly who. For an assumed role there is no userName; the session name is the last part of the ARN. Watchtower works this out and stores it as <code>actor</code>.</li>
<li><b>sourceIPAddress</b>: where the call came from. Sometimes it is an AWS service name (like <code>cloudtrail.amazonaws.com</code>) instead of an address, which means AWS made the call for you.</li>
<li><b>userAgent</b>: the browser, CLI or SDK. A user who always uses the console suddenly showing a scripting tool is worth a look.</li>
<li><b>errorCode</b>: present only when the call failed, for example <code>AccessDenied</code>. Watchtower sets <code>outcome</code> to failure when it is there. A run of <code>AccessDenied</code> errors often means someone is testing what a stolen key can do.</li>
<li><b>additionalEventData.MFAUsed</b>: on sign-ins, <code>Yes</code> or <code>No</code>. The rule "Console sign-in without MFA" reads this field.</li>
<li><b>readOnly</b>: <code>true</code> for looking (List, Describe, Get), <code>false</code> for changing something. Writes deserve more attention than reads.</li>
<li><b>awsRegion</b>: where it happened. Sign-ins and IAM calls are recorded in <code>us-east-1</code> no matter where you are. A write in a region the account never uses is suspicious (attackers like quiet regions for crypto miners).</li>
</ul>

<h3>Two quirks worth knowing</h3>
<ul>
<li>A failed console sign-in usually has no <code>errorCode</code>. Instead <code>responseElements.ConsoleLogin</code> is <code>Failure</code>. Watchtower checks for this so those still count as failures.</li>
<li>When someone types a user name that does not exist, AWS hides it and records <code>HIDDEN_DUE_TO_SECURITY_REASONS</code> instead. Lots of those from one address is guessing.</li>
</ul>

<h3>Read one yourself</h3>
<p>Go to <a href="/events?q=ConsoleLogin&amp;range=7d">Log activity filtered to ConsoleLogin</a> and click any row. The drawer that opens shows the raw log. Find each field above in it and say out loud what it tells you.</p>""",
     "try": [("Open recent console sign-ins and click a row", "/events?q=ConsoleLogin&range=7d"),
             ("Look for failed AWS calls", "/events?q=AccessDenied&range=7d"),
             ("Find calls that changed something in IAM", "/events?q=iam.amazonaws.com&range=7d")],
     "check": [("A record has userIdentity.type AssumedRole and no userName. How do you find out who it was?",
                "Read the ARN. For an assumed role it ends with role-name/session-name, and the session name is usually the person. Watchtower stores that as the actor."),
               ("What does readOnly: false tell you?",
                "The call changed something (created, deleted, modified) instead of just looking. Writes deserve more attention."),
               ("Why might a ConsoleLogin failure have no errorCode?",
                "AWS records failed console sign-ins in responseElements.ConsoleLogin as Failure. Watchtower checks that field too.")]},

    {"id": "magnitude", "title": "Magnitude: why a SIEM ranks", "minutes": 4, "body": """<p>A busy SIEM produces more offenses than anyone can read. If every alert rang the same bell, you would learn to ignore the bell. So a SIEM ranks: it puts the few offenses that matter at the top, and you work down the list. Watchtower ranks by <b>magnitude</b>, from 1 to 10, built from three parts.</p>

<h3>The three parts</h3>
<ul>
<li><b>Severity</b> (1 to 10): how bad it is if it is real. The root account being used is 9. A new network for a user is 4. Set on the rule.</li>
<li><b>Credibility</b> (1 to 10): how sure we are that a hit means something. A posture finding read straight from AWS is 10 (it is a fact). A sign-in from a new country is 6 (travel and VPNs cause plenty of them). Set on the rule.</li>
<li><b>Relevance</b> (1 to 10): how much this entity matters, plus how much activity there was. Important entities (like root or this PC) start at 7, everything else at 4. Then it goes up by one each time the event count doubles.</li>
</ul>

<h3>The formula</h3>
<pre>magnitude = 0.5 * severity + 0.2 * credibility + 0.3 * relevance
            (rounded, kept between 1 and 10)</pre>
<p>Severity carries the most weight on purpose: a likely-false alarm about something terrible should still outrank a sure thing that does not matter.</p>

<h3>Two worked examples</h3>
<table>
<tr><th>Offense</th><th>Severity</th><th>Credibility</th><th>Relevance</th><th>Magnitude</th></tr>
<tr><td>Root account used, 1 event</td><td>9</td><td>9</td><td>7 (root is important)</td><td>4.5 + 1.8 + 2.1 = 8.4, so 8</td></tr>
<tr><td>Account used from a new network, 1 event</td><td>4</td><td>5</td><td>4</td><td>2.0 + 1.0 + 1.2 = 4.2, so 4</td></tr>
</table>
<p>The root offense pings Discord (7 or more). The new-network one waits quietly on the <a href="/offenses">Offenses</a> page for you to read when you have time.</p>

<h3>Magnitude grows</h3>
<p>Relevance counts events, so an offense that keeps collecting hits climbs. Three failed sign-ins and thirty failed sign-ins are the same rule, but thirty is a bigger story, and the magnitude shows it.</p>

<h3>What magnitude is not</h3>
<p>It is a sort order, not a verdict. A magnitude 8 can be benign (you used root on purpose to set up MFA). A magnitude 4 can be the first sign of something real. Always work the top of the list first, but read the low ones too, especially when the same entity keeps showing up.</p>""",
     "try": [("Sort open offenses by magnitude", "/offenses"),
             ("Compare severity and credibility across rules", "/rules")],
     "check": [("Which of the three parts carries the most weight, and why?",
                "Severity, at 0.5. A possible false alarm about something very damaging should still rank above a certain but harmless finding."),
               ("A rule has severity 7 and credibility 7. One entity (not on the important list) hits it 3 times. What is the magnitude?",
                "Relevance is 4 plus 1 (3 events is more than one doubling), so 5. Then 3.5 + 1.4 + 1.5 = 6.4, rounded to 6. It does not ping Discord."),
               ("Does a high magnitude mean the offense is a true-positive?",
                "No. Magnitude decides what you read first. Only your triage decides the verdict.")]},

    {"id": "mitre-attack", "title": "MITRE ATT&CK", "minutes": 4, "body": """<p>MITRE ATT&amp;CK is a shared catalogue of the things attackers actually do, collected from real incidents. It gives everyone the same words. When you say "T1110" to another analyst, an interviewer or a vendor, they know you mean brute force, without any more explanation.</p>

<h3>Tactics and techniques</h3>
<ul>
<li>A <b>tactic</b> is the attacker's goal at that step: why. Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Collection and so on.</li>
<li>A <b>technique</b> is how they reach that goal. Brute Force, Account Manipulation, Disable or Modify Cloud Logs.</li>
<li>Some techniques have <b>sub-techniques</b> that narrow it down to one platform or method.</li>
</ul>

<h3>Reading T1078.004</h3>
<ul>
<li><code>T1078</code> is the technique: <b>Valid Accounts</b>. The attacker signs in with real credentials instead of breaking anything.</li>
<li><code>.004</code> is the sub-technique: <b>Cloud Accounts</b>. The account is a cloud login, like an AWS IAM user.</li>
</ul>
<p>One technique can serve more than one tactic. In Watchtower, "Console sign-in without MFA" maps T1078.004 to Initial Access (getting in), while "Root account used" maps the same technique to Privilege Escalation (getting the most power).</p>

<h3>Why every rule carries one</h3>
<ul>
<li><b>It explains the rule.</b> The rule "CloudTrail stopped, deleted or changed" is T1562.008, Impair Defenses: the attacker is blinding you.</li>
<li><b>It shows your gaps.</b> List your rules by tactic. If nothing covers Exfiltration, you know where to build next.</li>
<li><b>It helps you think ahead.</b> If you see Credential Access (T1110, brute force), the next steps in a real attack are often Initial Access and then Persistence (T1098, a new key or user). Go look for them.</li>
</ul>

<h3>Some you will see here</h3>
<table>
<tr><th>Rule</th><th>Technique</th><th>Tactic</th></tr>
<tr><td>Repeated console sign-in failures</td><td>T1110 Brute Force</td><td>Credential Access</td></tr>
<tr><td>IAM user, key or policy changed</td><td>T1098 Account Manipulation</td><td>Persistence</td></tr>
<tr><td>Security group opened to the internet</td><td>T1562.007 Disable or Modify Cloud Firewall</td><td>Defense Evasion</td></tr>
<tr><td>Activity in a new AWS region</td><td>T1535 Unused/Unsupported Cloud Regions</td><td>Defense Evasion</td></tr>
<tr><td>Windows event log cleared</td><td>T1070.001 Clear Windows Event Logs</td><td>Defense Evasion</td></tr>
</table>

<h3>Where to see it</h3>
<p>Every rule's technique is in the MITRE ATT&amp;CK column on <a href="/rules">Rules</a>, and on each offense page next to "Why this rule fired". The technique id links to its page on attack.mitre.org, which lists real examples and ideas for detection. When you build a rule in <a href="/rules/new">the rule builder</a>, you pick its MITRE id too.</p>""",
     "try": [("Read the MITRE column on every rule", "/rules"),
             ("Open an offense and follow its technique link", "/offenses")],
     "check": [("In T1562.008, what is the part before the dot and what is the part after?",
                "T1562 is the technique (Impair Defenses). .008 is the sub-technique (Disable or Modify Cloud Logs)."),
               ("What is the difference between a tactic and a technique?",
                "The tactic is the attacker's goal at that step (why). The technique is the method they use to get there (how)."),
               ("You see a brute force offense for a user. What should you look for next?",
                "Signs it worked and what came after: a successful sign-in for that user (Initial Access), then new keys, users or policies (Persistence, T1098).")]},

    {"id": "baselines", "title": "Baselines and \"new\"", "minutes": 5, "body": """<p>Some attacks look exactly like normal work. A stolen password signs in the same way the real owner does. The difference is often where and how, compared to what that person usually does. That "usual" is a <b>baseline</b>.</p>

<h3>What Watchtower learns</h3>
<p>Before the rules see an AWS event, <code>enrich.py</code> checks it against three baselines:</p>
<ul>
<li><b>new country</b>: this user has signed in to the console before, but never from this country. The country comes from an offline lookup of the address, so nothing is sent anywhere.</li>
<li><b>new network</b>: this IAM user or root has been seen before, but never from this network (the first two parts of the address, a /16). Usually a new Wi-Fi or phone hotspot.</li>
<li><b>new region</b>: the account has history, but has never had a write (a change, not a read) in this AWS region.</li>
</ul>
<p>Three rules fire on those flags: "Sign-in from a new country", "Account used from a new network" and "Activity in a new AWS region".</p>

<h3>Why the first value is not an alert</h3>
<p>"New" only means something if there is history to compare with. The very first country a user ever signs in from is not new, it is the start of their baseline. So Watchtower only flags a value when that user already has history and this value is not in it. This is the <b>learning period</b>. On its first run Watchtower also reads every AWS event already stored and learns from all of them without flagging anything, so the backfilled week becomes the starting baseline instead of a flood of alerts.</p>
<p>The trade-off: anything bad that happened during the learning period becomes "normal". A baseline built from a compromised week would hide the compromise. That is one reason to read the first days of a new data source by hand.</p>

<h3>What false alarms look like</h3>
<ul>
<li><b>Travel</b>: you sign in from another country on holiday. Benign.</li>
<li><b>VPN</b>: a VPN exit node puts you in a country or network you have never been in. Benign, and it will keep happening each time the VPN picks a new exit.</li>
<li><b>New Wi-Fi</b>: a coffee shop, campus or phone hotspot is a new network. This is why "new network" has severity 4 and credibility 5. It is a clue, not an alarm.</li>
</ul>
<p>Each value is learned once. After you sign in from the campus network once, it is in your baseline and does not fire again.</p>

<h3>How to tell real from benign</h3>
<p>Look at what happened after the new sign-in. A tourist reads their usual pages. An attacker lists users, creates access keys, or starts something in a new region. If the same actor also trips another rule within a day, the correlation rule ("One entity tripped several rules") opens its own offense. That combination is much more convincing than either one alone.</p>

<h3>How to tune</h3>
<ul>
<li>Close benign ones as <b>benign</b> with a note ("VPN exit, known"). Your <a href="/analyst">analyst log</a> will then show which rules make the most benign closes.</li>
<li>If one rule is mostly noise, turn it off on <a href="/rules">Rules</a> and build a narrower version in <a href="/rules/new">the rule builder</a>, for example only for console sign-ins, or only with a higher threshold.</li>
<li>Do not tune by deleting the alert you are tired of. Tune by making the rule ask a sharper question.</li>
</ul>""",
     "try": [("Find new-country and new-network offenses", "/offenses"),
             ("Look at one user's sign-ins over a week", "/events?q=ConsoleLogin&range=7d"),
             ("See which rules you close as benign most", "/analyst")],
     "check": [("Why doesn't the first country a user ever signs in from raise an alert?",
                "There is no history to compare it with. The first value is learning: it becomes the start of that user's baseline."),
               ("What is the risk of a learning period?",
                "Anything bad that happened during it is learned as normal and will not be flagged later."),
               ("A new-network sign-in fires for a user. What would make you more worried?",
                "What happens next: IAM changes, new access keys, activity in a new region, or the same user tripping another rule within a day (a correlation offense).")]},

    {"id": "detection-engineering", "title": "Detection engineering", "minutes": 6, "body": """<p>Detection engineering is writing the rules a SIEM runs, and keeping them useful. A good rule fires on the thing you care about and rarely on anything else. Getting there is a loop, not a single step.</p>

<h3>The loop</h3>
<ol>
<li><b>Idea</b>: start from a behaviour, not a log field. "Someone is guessing one user's password" is an idea. Good sources: a MITRE technique you have no rule for, an offense you triaged and wished had fired earlier, a drill.</li>
<li><b>Rule</b>: turn the idea into conditions on the normalized fields: source, action, outcome, a field that contains some text, and how to group.</li>
<li><b>Test against history</b>: run it over the last 7 days before you ship. How often would it have fired? On what?</li>
<li><b>Tune</b>: adjust threshold and window until it fires on the bad pattern and stays quiet on normal days.</li>
<li><b>Ship</b>: save it. It now runs on every new event.</li>
<li><b>Watch the false-positive rate</b>: after a week or two, look at how you closed its offenses. Mostly false-positive or benign means go back to step 4.</li>
</ol>

<h3>Example: failed console sign-ins for one user</h3>
<p>Watchtower already has "Repeated console sign-in failures", which groups by <b>source address</b> (3 failures from one address in 15 minutes). An attacker who spreads guesses across many addresses would slip past it. So write a rule that groups by <b>user</b> instead. Open <a href="/rules/new">the rule builder</a> and fill it in:</p>
<table>
<tr><th>Field</th><th>Value</th><th>Why</th></tr>
<tr><td>Name</td><td>Many failed console sign-ins for one user</td><td>Say what it catches, in plain words.</td></tr>
<tr><td>Source</td><td>aws-cloudtrail</td><td>Console sign-ins are CloudTrail events.</td></tr>
<tr><td>Actions</td><td>ConsoleLogin</td><td>Only sign-in attempts.</td></tr>
<tr><td>Outcome</td><td>failure</td><td>Only the failed ones.</td></tr>
<tr><td>Condition</td><td>(leave empty)</td><td>Use one later if you need to exclude something.</td></tr>
<tr><td>Group by</td><td>actor</td><td>One offense per user, whatever the address.</td></tr>
<tr><td>Window</td><td>30 minutes</td><td>Long enough to catch slow guessing.</td></tr>
<tr><td>Threshold</td><td>5</td><td>People mistype once or twice; five in half an hour is unusual.</td></tr>
<tr><td>Severity</td><td>6</td><td>Bad if it works, but failures alone mean nothing got in yet.</td></tr>
<tr><td>Credibility</td><td>6</td><td>A forgotten password looks the same.</td></tr>
<tr><td>MITRE</td><td>T1110</td><td>Brute Force, Credential Access.</td></tr>
</table>
<p>Now press <b>Test against the last 7 days</b>. Read the result honestly:</p>
<ul>
<li><b>Zero hits</b> is fine if nobody failed to sign in. It does not prove the rule works. Run a drill or think about whether the conditions could ever match.</li>
<li><b>A few hits, all one person on one morning</b> is probably a forgotten password. Look at them. Would you want to be told? If yes, ship it.</li>
<li><b>Hits every day</b> means the threshold is too low or the window too long. Raise the threshold, shorten the window, test again.</li>
</ul>
<p>Watch out for one quirk: when a guessed user name does not exist, AWS hides it as <code>HIDDEN_DUE_TO_SECURITY_REASONS</code>, so all of those failures group under that one "user". That is still worth an offense.</p>

<h3>Threshold and window, together</h3>
<p>The window is how far apart hits can be and still count together. The threshold is how many hits it takes to open an offense. A low threshold with a long window is noisy. A high threshold with a short window misses slow attacks. Change one at a time and test after each change, so you know which one helped.</p>

<h3>After you ship</h3>
<p>Your verdicts are the feedback. If your new rule's offenses keep closing as false-positive, the rule matches things you did not mean it to. If they keep closing as benign, it is catching real activity that you do not care about, so narrow it with a condition. Keep the note on each close short and specific so the pattern is easy to see in your <a href="/analyst">analyst log</a>.</p>""",
     "try": [("Build the example rule and test it", "/rules/new"),
             ("Compare it with the built-in failures rule", "/rules"),
             ("Run a drill to see if it fires", "/drills")],
     "check": [("Why does the example rule group by actor instead of source address?",
                "So guessing spread across many addresses still adds up under one user. The built-in rule groups by address and would miss that."),
               ("The test shows the rule firing every day. What do you change first?",
                "Raise the threshold or shorten the window, one at a time, and test again after each change."),
               ("Zero hits in the 7-day test. Does that mean the rule works?",
                "No. It only means nothing matched last week. Check that the conditions could match, for example with a drill.")]},

    {"id": "watching-the-watcher", "title": "Watching the watcher", "minutes": 4, "body": """<p>A SIEM that stopped receiving logs looks exactly like a SIEM with nothing to report. Both show an empty, calm Overview. Attackers know this: turning off logging is one of the first things a careful one does. So a SIEM has to watch its own feeds, and it has to be built so that it cannot become the weak point itself.</p>

<h3>Silent feeds</h3>
<p>After every collector run, Watchtower checks each feed. If one has not succeeded for three of its normal intervals (and at least 30 minutes), it writes an event about itself, and a normal rule opens an offense:</p>
<ul>
<li><b>A log feed went silent</b> (severity 7, credibility 10). Something is wrong and anything happening in that source is invisible to you.</li>
<li><b>AWS login expired</b> (severity 5). The read-only AWS sign-in timed out, so AWS data stopped. Not an attack, but you are still blind until you sign in again.</li>
</ul>
<p>Both close themselves with a note once the feed delivers again. The morning summary also says either "Feeds: all delivering" or which feeds are down.</p>
<p>Habit to build: when the Overview looks quiet, check the Collectors table before you relax. Quiet with all feeds green is good news. Quiet with a red feed is no news at all.</p>

<h3>Least privilege</h3>
<p>A SIEM reads everything, so it is a juicy target. If an attacker took it over, what could they do with its access? Watchtower is built so the answer is "read logs, and nothing else".</p>
<ul>
<li><b>AWS</b>: Watchtower uses a <b>read-only</b> SSO role. It can list and describe; it cannot create, change or delete anything. The code refuses to start with a profile whose name suggests write access. SSO sessions are short (a few hours), so a stolen session expires on its own. That is also why "AWS login expired" exists.</li>
<li><b>No long-lived keys</b>: there are no AWS access keys stored on disk. When it moves to a server, the plan is an instance role, again with no keys.</li>
<li><b>Windows</b>: the Security log normally needs an administrator. Instead of running Watchtower as admin, the account is in the built-in <b>Event Log Readers</b> group, which grants reading event logs and nothing more. If Watchtower were compromised, the attacker would not get admin on the PC.</li>
<li><b>What leaves the machine</b>: Discord pings carry a title, an entity and a link. IP addresses, ARNs and key ids are stripped out before sending. Raw logs never leave.</li>
<li><b>The console</b>: it listens only on this PC and the tailnet, and every sign-in and change is recorded on the <a href="/audit">Audit log</a>.</li>
</ul>

<h3>Why this matters for you</h3>
<p>In a real SOC you will be asked "what happens if your tooling is compromised?" and "how would you know if a log source died?". Being able to point at a silent-feed rule and a read-only design is a strong answer.</p>""",
     "try": [("Check the Collectors table on the Overview", "/"),
             ("Find the self-monitoring rules", "/rules"),
             ("Read who did what in the console", "/audit")],
     "check": [("Why is a quiet SIEM dangerous?",
                "Quiet can mean nothing happened or that logs stopped arriving. From the dashboard alone they look the same."),
               ("Why use the Event Log Readers group instead of running Watchtower as admin?",
                "Least privilege. The group allows reading event logs only, so a compromised Watchtower would not hand an attacker admin rights."),
               ("What does a short SSO session protect against?",
                "A stolen session token stops working on its own within hours, instead of staying valid like a long-lived access key.")]},

    {"id": "interviews", "title": "Talking about it in interviews", "minutes": 5, "body": """<p>Watchtower is a strong thing to talk about, as long as you describe it honestly. Interviewers ask follow-up questions, and the honest version holds up under them.</p>

<h3>The honest framing</h3>
<ul>
<li><b>You directed it.</b> You decided what Watchtower should collect, detect and show, and you used an AI coding assistant to write the code. Say that plainly. Directing AI to build working security tooling is a real and current skill.</li>
<li><b>You operate it.</b> You triage the offenses, pick the verdicts, write the notes, and run the drills.</li>
<li><b>You write the detections.</b> You design rules, test them against history, and tune them.</li>
<li><b>Never claim you hand-coded it.</b> If asked to walk through code, talk about the design: why events are normalized, how magnitude is computed, why the AWS role is read-only.</li>
</ul>
<p>A one-line version: "I built my own small SIEM by directing an AI coding assistant, and I use it the way a SOC analyst would: I triage its alerts and write and tune its detection rules."</p>

<h3>STAR</h3>
<p>Behavioural questions are easiest to answer with STAR:</p>
<ul>
<li><b>Situation</b>: the context, in one or two sentences.</li>
<li><b>Task</b>: what you had to do.</li>
<li><b>Action</b>: what you did, step by step. This is the longest part.</li>
<li><b>Result</b>: what happened, with a number if you have one, and what you learned.</li>
</ul>
<p>Use your own real cases from your <a href="/analyst">analyst log</a>. The examples below are templates; replace the details with what actually happened.</p>

<h3>Example 1: "Tell me about a time you investigated an alert."</h3>
<p><b>S:</b> I run a small SIEM on my own AWS account and home PC. One morning it raised a magnitude 7 offense: a console sign-in from a country that user had never signed in from before.</p>
<p><b>T:</b> Decide whether it was an account takeover and act if it was.</p>
<p><b>A:</b> I read why the rule fired, then opened the raw CloudTrail event. MFA was used and the browser matched the user's normal one. I searched that user's activity for the week: no IAM changes, no new access keys, nothing in unused regions afterwards. Then I confirmed with the user that they were travelling.</p>
<p><b>R:</b> I closed it as benign with a note listing the evidence. It also showed me that the rule fires on every trip, so I now check what happens after a new-country sign-in before anything else.</p>

<h3>Example 2: "Tell me about a detection you built."</h3>
<p><b>S:</b> My SIEM's brute force rule grouped failed AWS console sign-ins by source address.</p>
<p><b>T:</b> An attacker spreading guesses across many addresses would never hit the threshold, so I wanted a rule that caught guessing against one user.</p>
<p><b>A:</b> I wrote a rule for failed ConsoleLogin events grouped by user, 5 failures in 30 minutes, mapped to MITRE T1110. Before shipping it I tested it against the last 7 days of logs and checked that the hits it found were ones I would want to see. Then I ran a practice drill to make sure it fired.</p>
<p><b>R:</b> It caught the drill and stayed quiet on normal days. I track its verdicts afterwards to watch the false-positive rate.</p>

<h3>Questions to be ready for</h3>
<ul>
<li>"What is the difference between a false-positive and a benign alert?" (Lesson 2.)</li>
<li>"How do you rank alerts?" (Lesson 4: severity, credibility, relevance.)</li>
<li>"How would you know if a log source stopped?" (Lesson 8.)</li>
<li>"How did you limit what your SIEM can do?" (Read-only role, Event Log Readers, short sessions.)</li>
</ul>""",
     "try": [("Pick a real case for your STAR answer", "/analyst"),
             ("Run a drill to get a fresh story", "/drills"),
             ("Review a rule you could talk about", "/rules")],
     "check": [("How do you describe who built Watchtower?",
                "You directed an AI coding assistant to build it. You decide what it detects, triage its alerts, and write and tune its rules. Never claim you hand-coded it."),
               ("Which part of a STAR answer should be the longest?",
                "Action: the specific steps you took yourself."),
               ("Where should the details of your STAR stories come from?",
                "Your own closed offenses and notes in the analyst log, not the template examples.")]},
]
