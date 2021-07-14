#!/usr/bin/python3

try:
    import time
    from sys import __stdout__, stdout
    from threading import Thread
    from subprocess import *
    import os
    import sys
    import subprocess
    import threading
    import readline
    from art import*
    from termcolor import colored
except ImportError:
    print("\ncheck for prerequisities ")

fileObject = ''
fileName = ''
folderName = ''
target = ''


def acquireTarget():
    global target
    os.system('clear')
    target = str(input("Enter target URL (exclude www): "))
    print('\x1b[1;32m' + '\n[OK]\t' + '\x1b[0m' + 'Target Acquired')


# ============Initiate recon with subdomain scan=====================


def subdomain():

    os.system('clear')
    p = './subdomains/'
    try:
        os.mkdir(p)

    except FileExistsError as exc:
        print(exc)

    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Start collecting resolved Subdomains", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    global target
    global fileObject
    cmd = [
        ' subfinder -d ' + target + ' -o subfinder_psub.txt',
        ' assetfinder --subs-only ' + target + '| anew -q assetfinder_psub.txt',
        ' amass enum -passive -d ' + target +
        ' -config ~/.config/amass/config.ini -o amass_psub.txt',
        ' findomain -t ' + target + ' -u findomain_psub.txt',
        ' waybackurls ' + target + '| unfurl --unique domains | anew -q waybackurls_psub.txt',
        ' gauplus -t 50 -subs ' + target +
        '|unfurl --unique domains | anew -q gau_psub.txt',
        'crobat -s ' + target + '|anew -q crobat_psub.txt',
        ' cat *_psub.txt | sed "s/*.//" | anew subdomains/passive_subs.txt | wc -l'
    ]
    try:

        for c in cmd:
            proc = subprocess.run(
                c, shell=True, stderr=STDOUT, stdout=sys.stdout)
            # err, out = proc.communicate()
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                  'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:

            fileObject = open('subdomains/probed_subdomains.txt', 'w+')
            subprocess.run("cat subdomains/passive_subs.txt | httpx -follow-host-redirects -status-code -threads 50 -timeout 15  -retries 2 -no-color | cut -d ' ' -f1 | grep '.{}$' | anew ".format(
                target), shell=True, stdout=fileObject)

            print(colored("[x] Executed", 'blue', attrs=['bold']))
            print(colored(">> Cleaning the temporary files << ",
                  'yellow', attrs=['bold']))
            subprocess.run('rm *_psub.txt', shell=True, stdout=PIPE)
    except:
        print("Something went wrong! Trying again\n")

    return 0


# ============Continue recon with Port scan and dns =====================

def portscan():
    os.system('clear')
    p = './hosts/'
    try:
        os.mkdir(p)

    except FileExistsError as exc:
        print(exc)

    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Start collecting resolved ips", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    global target
    # global fileObject
    cmd = [
        'for sub in $(cat subdomains/passive_subs.txt);do echo "$sub $(dig +short a $sub | tail -n1)" | anew -q subs_ips.txt; done',
        "awk -F: '{ print $2 " " $1}' subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt ",
        "cat hosts/subs_ips_vhosts.txt | cut -d ' ' -f2| anew -q hosts/ips.txt "
    ]
    cmd1 = ['for sub in $(cat hosts/ips.txt); do shodan host $sub 2>/dev/null >> hosts/portscan_passive.txt && echo -e "\n\n#######################################################################\n\n" >> hosts/portscan_passive.txt; done',
            'nmap --top-ports 1000 -sV -n --max-retries 2 -iL hosts/ips.txt -oN hosts/portscan_active.txt '
            ]
    try:
        for c in cmd:
            proc = subprocess.run(c, shell=True, stderr=STDOUT, stdout=PIPE)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
            print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
            print(
                colored("[+] Starting Portscanning", 'red', attrs=['bold']))
            print(colored("--------------------------------------------",
                  'red', attrs=['bold']))

        for c1 in cmd1:
            proc1 = subprocess.run(
                c1, shell=True, stderr=STDOUT, stdout=sys.stdout)
        if(proc1.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc1.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
            subprocess.run('rm subs_ips.txt  ',
                           shell=True, stdout=PIPE)
    except:
        print("Something went wrong! Trying again\n")

    return 0

# =============Gathering SPF & DMARC RECORDS with Zonetransfer vulnerability.=========================================


def emailspoof_ZT():

    os.system('clear')
    p = './osint/'
    try:
        os.mkdir(p)

    except FileExistsError as exc:
        print(exc)
    dnsrecon = "~/Tools/dnsrecon/dnsrecon.py"
    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Start collecting information about target", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    print(colored("\n[*]\tRunning DNSRECON\n[*]", 'red', attrs=['bold']))
    global target
    # global fileObject
    cmd = [
        "python3 "+dnsrecon+" -d "+target+" -a -j osint/zt.json",
        "cat osint/zt.json | tee osint/Spoof_zonetransfer.txt"
    ]
    try:

        for c in cmd:
            proc = subprocess.run(c, shell=True, stderr=STDOUT, stdout=PIPE)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            subprocess.run(
                'rm  osint/zt.json', shell=True, stdout=PIPE)
            print(colored("[x] Executed", 'blue', attrs=['bold']))
    except:
        print("Something went wrong! Check prerequisities.\n")
    return 0

# ==================Nuclei checks======================


def nuclei_check():
    os.system('clear')
    p = './nuclei_output/'
    try:
        os.mkdir(p)

    except FileExistsError as exc:
        print(exc)
    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Starting Nuclei", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    print(colored("\n[*]\tRunning Nuclei scans\n[*]", 'red', attrs=['bold']))
    global target
    cmd = [
        'nuclei -ut',
        'cat subdomains/probed_subdomains.txt | nuclei -silent -t ~/nuclei-templates/ -severity info -r ../../resolvers_trusted.txt -o nuclei_output/info.txt',
        'cat subdomains/probed_subdomains.txt | nuclei -silent -t ~/nuclei-templates/ -severity low -r ../../resolvers_trusted.txt -o nuclei_output/low.txt',
        'cat subdomains/probed_subdomains.txt | nuclei -silent -t ~/nuclei-templates/ -severity medium -r ../../resolvers_trusted.txt -o nuclei_output/medium.txt'
        'cat subdomains/probed_subdomains.txt | nuclei -silent -t ~/nuclei-templates/ -severity high -r ../../resolvers_trusted.txt -o nuclei_output/high.txt',
        'cat subdomains/probed_subdomains.txt | nuclei -silent -t ~/nuclei-templates/ -severity critical -r ../../resolvers_trusted.txt -o nuclei_output/critical.txt'
    ]

    try:

        for c in cmd:
            proc = subprocess.run(c, shell=True, stderr=STDOUT, stdout=PIPE)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
    except:
        print("Something went wrong! Check prerequisities.\n")
    return 0

# ============= SSL TEST ==========================


def testssl():
    os.system('clear')
    p = './ssl_test/'
    try:
        os.mkdir(p)

    except FileExistsError as exc:
        print(exc)
    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Starting SSL TEST", 'red', attrs=['bold']))
    print(colored("--------------------------------------------", 'red', attrs=['bold']))
    print(colored("\n[*]\tRunning SSL TEST scans\n[*]", 'red', attrs=['bold']))
    global target
    cmd = [
        ' ~/Tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL hosts/ips.txt | tee ssl_test/ssltest.txt'
    ]

    try:

        proc = subprocess.run(cmd, shell=True, stderr=STDOUT, stdout=PIPE)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
    except:
        print("Something went wrong! Check prerequisities.\n")
    return 0

# ============= google dorking =====================


def dorks():
    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Starting Google dorking", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    print(colored(
        "\n[*]\tRunning Google dorks for potential find\n[*]", 'red', attrs=['bold']))
    global target
    cmd = [
        ' ~/Tools/degoogle_hunter/degoogle_hunter.sh ' +
        target + ' | tee osint/dorks.txt',
        'sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/dorks.txt'
    ]

    try:
        for c in cmd:
            proc = subprocess.run(c, shell=True, stderr=STDOUT, stdout=PIPE)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
    except:
        print("Something went wrong! Check prerequisities.\n")
    return 0
# ============= Github dorks ======================


def githubDorker():
    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Starting Github dorking", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    print(colored(
        "\n[*]\tRunning Github dorks for potential find\n[*]", 'red', attrs=['bold']))
    global target
    cmd = [
        'python3 ~/Tools/GitDorker/GitDorker.py -tf ~/Tools/.github_tokens -e 5 -q '+target +
        ' -p -ri -d ~/Tools/GitDorker/Dorks/medium_dorks.txt | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt',
        'sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/gitdorks.txt'
    ]

    try:
        for c in cmd:
            proc = subprocess.run(
                c, shell=True, stderr=STDOUT, stdout=sys.stdout)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
    except:
        print("Something went wrong! Check prerequisities.\n")
    return 0
# =============  scanner =======================


def cms_scan():
    os.system('clear')
    p = './cms/'
    try:
        os.mkdir(p)

    except FileExistsError as exc:
        print(exc)
    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Starting cms scanner", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    print(colored("\n[*]\tRunning cms scanner", 'red', attrs=['bold']))
    global target
    cmd = [
        "tr '\n' ',' < subdomains/probed_subdomains.txt > cms/cms.txt",
        'python3 ~/Tools/CMSeeK/cmseek.py -l cms/cms.txt --batch -r ',
    ]
    cmd1 = [
        "for sub in $(cat subdomains/probed_subdomains.txt);do sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||') cms_id=$(cat ~/Tools/CMSeeK/Result/${sub_out}/cms.json | jq -r '.cms_id');if [[ -z ${cms_id}]];then rm -rf ~/Tools/CMSeeK/Result/${sub_out}; else mv -f ~/Tools/CMSeeK/Result/${sub_out} ./cms/; fi; done"
    ]
    try:
        for c in cmd:
            proc = subprocess.run(
                c, shell=True, stderr=STDOUT, stdout=sys.stdout)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))

        print(
            colored("[+] Saving Output", 'red', attrs=['bold']))

        proc1 = subprocess.run(cmd1, shell=True, stderr=STDOUT, stdout=PIPE)
        if(proc1.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc1.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
    except:
        print("Something went wrong! Check prerequisities.\n")
    return 0
# =============CORS test==========================


def cors():
    print(colored("\n--------------------------------------------",
                  'red', attrs=['bold']))
    print(
        colored("[+] Starting CORSy", 'red', attrs=['bold']))
    print(colored("--------------------------------------------",
                  'red', attrs=['bold']))
    print(colored("\n[*]\tRunning CORS test\n[*]", 'red', attrs=['bold']))
    global target
    cmd = [
        'python3 ~/Tools/Corsy/corsy.py -i subdomains/probed_subdomains.txt > subdomains/cors.txt ',
        '[ -s "subdomains/cors.txt" ] && cat subdomains/cors.txt'
    ]

    try:
        for c in cmd:
            proc = subprocess.run(
                c, shell=True, stderr=STDOUT, stdout=sys.stdout)
        if(proc.returncode != 0):
            print(colored('Step 1 Failed! Check/Update prerequisitie packages. \nError: ',
                          'blue', attrs=['bold']) + proc.stderr.rstrip())
            sys.exit(1)
        else:
            print(colored("[x] Executed", 'blue', attrs=['bold']))
    except:
        print("Something went wrong! Check prerequisities.\n")
    return 0
# ============ MAIN ==============================


def main():
    global fileObject
    global target
    global fileName, folderName
    global scans, disabled
    disabled = list()
    scans = [
        portscan, emailspoof_ZT, nuclei_check, testssl, dorks, githubDorker, cms_scan, cors
    ]
    dummy = scans
    print("------------------------------------------------------------")
    recon_tool = text2art("   Recon-tool", "cybermedium")
    print(colored(recon_tool, 'blue', attrs=['blink', 'bold'])) 
    print("------------------------------------------------------------")
    
    try:
        while True:
            print("\n------------------------------------------------------------")
            print(colored("1.\tEnter Target Information", 'yellow', attrs=['bold']))
            print(colored("2.\tCreate Output File", 'yellow', attrs=['bold']))
            print(colored("3.\tInitiate Recon", 'yellow', attrs=['bold']))
            print(colored("4.\tDisable a scan", 'yellow', attrs=['bold']))
            print("------------------------------------------------------------")
            if (target == ''):
                print('\x1b[1;31m' + '\n[!]\t' + '\x1b[0m' +
                      'Target missing. Select 1 to enter target URL')
            else:
                print('\x1b[1;32m' + '\n[OK]\t' +
                      '\x1b[0m' + 'Scope: %s' % target)

            if (fileObject == ''):
                print('\x1b[1;31m' + '[!]\t' + '\x1b[0m' +
                      'Select 2 to enter output file name')
            try:
                option = int(
                    input("\nEnter your option or Press Ctrl+C to exit: "))
            except Exception as e:
                print(colored("\nNo valid choice given! Please try again ...\n", 'red', attrs=['blink', 'bold']))
                time.sleep(5)
                sys.exit()
            if(option == 1):
                acquireTarget()
            elif(option == 4):
                for i in dummy:
                    count = 0
                    for i in scans:
                        print(str(count) + "." + str(i.__name__))
                        count += 1
                    try:
                        n = int(
                            input(colored("\nEnter the scan number:\n", 'cyan', attrs=['bold'])))
                        scans.pop(n)
                    except Exception as e:
                        print(colored(e, 'red', attrs=['blink', 'bold']))
                    try:
                        exit = str(input(colored(
                            "\nPress enter to disable another scan "+"\nor Type exit to continue scanning:\n", 'blue')))
                        if(exit == 'exit' or exit == 'EXIT'):
                            break
                        elif exit == '':
                            pass
                        elif (exit != 'exit' or exit != 'EXIT'):
                            raise Exception(
                                print(colored("\nGive valid entry\n", 'red', attrs=['blink', 'bold'])))
                        
                    except Exception as e:
                        print(e)
                        pass
                print(colored("\nThese scans will be performed:\n",
                      'yellow', attrs=['bold']))

                for j in scans:
                    print(colored(str(j.__name__), 'magenta', attrs=['bold']))

            elif(option == 3):
                if(target == '' or fileObject == ''):
                    print('\x1b[1;31m' + '[!]\t' + '\x1b[0m' +
                          'Target or Filename missing!')
                else:
                    os.system('clear')

                    print('\n\t\t(' + '\x1b[1;31m' + ' RUN ' + '\x1b[0m' +
                          '|' + '\x1b[1;34m' + ' NO ' + '\x1b[0m' + ')')
                    authorisation = str(input("\nWaiting for input: "))
                    if(authorisation == 'run' or authorisation == 'RUN'):
                        print(colored("\nCommencing Recon .....", 'cyan', attrs=['blink', 'bold']))
                        if os.path.isfile("subdomains/passive_subs.txt"):
                            pass
                        else:

                            subdomain()
                        c=0    
                        join_list = []
                        for i, j in enumerate(scans):
                            i = threading.Thread(target=j)
                            i.start()
                            c+=1
                            if c != 1 :
                                i.join(timeout=5)
                                                
                    else:
                        fileObject.close()
                        sys.exit(0)
            elif(option == 2):
                os.system('clear')
                folderName = str(input("Enter output filename: "))

                if not os.path.exists("Output"):
                    os.makedirs("Output")
                if not os.path.exists("Output/"+folderName):
                    os.makedirs("Output/"+folderName+"/")
                fileObject = os.chdir('./Output/'+folderName)
                print("[OK]\t/Output/%s/%s created." % (folderName, fileName))
            else:
                os.system('clear')
                print(colored("\n Invalid option\n", 'red', attrs=['blink', 'bold']))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
