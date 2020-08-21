import os
toc = []
toc.append("- file: intro")
toc.append("- file: tactics")
toc.append("  sections:")
arr = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection',  'command-and-control', 'exfiltration', 'impact']
for j in arr:
    path = os.path.join(os.getcwd(), "playbook", "tactics", j)
    toc.append("    - file: tactics/{0}".format(j))
    toc.append("      sections:")
    for i in os.listdir(path):
        toc.append("        - file: tactics/{0}/{1}".format(j,i))

with open("toc.yml","w") as f:
    f.write("\n".join(toc))
