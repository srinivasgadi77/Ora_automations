#!/usr/local/python3/bin/python3.6
import os

def ldapByMailId(ldap):
    mail_id={
      'esoltwed' : 'eric.soltwedel@oracle.com',
      'kcarroll' : 'katherine.carroll@oracle.com',
      'mwolak'   : 'michael.wolak@oracle.com',
      'rgoldthw' : 'robert.goldthwait@oracle.com',
      'hcornejo' : 'hector.cornejo@oracle.com',
      'kfordyce' : 'ken.fordyce@oracle.com',
      'pszilva'  : 'peter.szilva@oracle.com',
      'tpynadat' : 'tisson.pynadath@oracle.com',
      'jbui'     : 'james.bui@oracle.com',
      'kbayiset' : 'krishna.bayisetti@oracle.com',
      'ranwilso' : 'randal.wilson@oracle.com',
      'prask'    : 'prashanth.k@oracle.com',
      'rarashuk' : 'rahul.rs.shukla@oracle.com',
      'tanmdas'  : 'tanmoy.das@oracle.com',
      'srgadi'   : 'srinivas.gadi@oracle.com',
      'egoel'    : 'ekta.goel@oracle.com',
      'dpallipa' : 'dheepakkumar.pan@oracle.com',
      'mvheath'  : 'michael.v.heath@oracle.com',
      'gridley'  : 'george.ridley@oracle.com',
      'dmccrea'  : 'david.mccrea@oracle.com',
      'kechan'   :  'ken.chan@oracle.com',
      'canantha' :  'chithan.ananthan@oracle.com',
      'shmanne' : 'shiva.kumar.reddy.manne@oracle.com',
      'rizwamoh' : 'rizwan.a.mohammed@oracle.com',
      'cmsk'     :  'chaitanya.m.s.k@oracle.com',
      'banvenka' : 'bandaru.venkataramana@oracle.com',
      'kopatil' : 'kirangouda.patil@oracle.com',
      'mur' : 'muniraja.r@oracle.com',
      'rlingamg' : 'rangarao.lingamgunta@oracle.com',
      'vtpawar' : 'vikas.t.pawar@oracle.com',
      'vkhanuma' : 'vijay.hanumantha@oracle.com',
      'ykrajash' : 'yashavantha.rajashekar@oracle.com',
      'vauruvap' : 'vijayakumar.auruvappagowder@oracle.com',
      'rswamygo' : 'raja.swamygowda@oracle.com',
      'sguttura' : 'srinivas.gutturashok@oracle.com'
    }
    return mail_id[ldap]

def write_to_file(mail_content):
    f = open('/tmp/content_mail.txt','w')
    for data in mail_content:
          f.write(data)
    f.close()

    #os.system("sed '1{/^$/d}' /tmp/content_mail.txt > /tmp/content_mail.txt") 
    cmd="awk '{$1=$1};1' /tmp/content_mail.txt | grep -v ^$ > /tmp/content_mail_clean.txt"
    os.system(cmd)

def format_content(cr_num,ldap,uname_cmd,prechk_cmd,ovm_patching_cmd,log_retrival,reboot):
  
    subject="%s:OIT Eng Pathing playbook commands" %cr_num
    to_user=ldapByMailId(ldap.strip())
 
    mail_content="""
       To:%s
       Subject:%s
       Content-Type: text/html
       <html>
       <body>
       
       <p><H2>OIT Eng Pathing playbook commands:</H2></p>
       
       <p><b>1. Uname:</b></p>
       <p>%s</p>
       
       <p><b>2. Pre-check:</b></p>
       <p>%s</p>
       
       <p><b>3. Patching:</b></p>
       <p>%s</p>
       
       <p><b>4.Collect logs:</b></p>
       <p>%s</p>
       
       
       <p style="color:red;"><b>5.Reboot(careful):</b></p>
       <p>%s</p>
       
       <p><b>NOTE:</b></p>
       <p> 1. To bring up bulk hosts post patch and reboot, refer the <a href="https://confluence.oraclecorp.com/confluence/display/OITPVM/Wakeup+ENG+DOMUs+in+bulk">Wake up script</a> to bring up quickly</p>
       <p> 2. Even hosts down, get HV details from <a href="https://devops.oraclecorp.com/host/search/">devOps</a> tool and check console manually</p>
       <p> 3. Still its an issue, log a <a href="https://myhelp.oracle.com/">SR</a> and post it in <a href="https://dyn.slack.com/archives/CEYSTDHGQ">#oit-compute-ops</a></p>
       </br>
       <p><i>For any enahancement / Bugs please log <a href="https://jira.oraclecorp.com/jira/secure/Dashboard.jspa">JIRA </a> by select project as "OIT-Compute Operations (OITOCO)". </i></p>
       
       
       </body>
       </html>
       """ %(to_user, subject, uname_cmd,prechk_cmd,ovm_patching_cmd,log_retrival,reboot)

    write_to_file(mail_content)

    send_mail(to_user)

def send_mail(to_user):
   
    print("--------------------")
#    print(mail_content) 
    print("--------------------")
    if to_user:
       #cmd="echo '%s' | mail -s '%s' %s" %(mail_content, subject, to_user)
       cmd="cat /tmp/content_mail_clean.txt | sendmail -t" 
       os.system(cmd)
       print('Mail has been sent to %s' %to_user)
    else:
       print('Failed to send mail as %s does not exists' %ldap)
