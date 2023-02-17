#!/usr/bin/env python

import argparse
from collections import Counter
import calendar
import time
import os
import re
import string
import sys
from typing import Dict, List
import tempfile
import shutil
import difflib

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS
import matplotlib.pyplot as plt

TEMPLATE = '''<html>
    <head>
        <title>{{page_title_text}}</title>
    </head>
    <body>
            <h1 style="align: center;">{{title_text}}</h1>
            <br>
            <p>Total hashes submitted: <b>{{total_user}}</b></p>
            <p>Passwords found: <b>{{cracked}}</b></p>
            <p>Passwords not found: <b>{{not_cracked}}</b></p>
            <p>Percent of recovered passwords: <b>{{cracked_pct}}%</b></p>
            <br>
            <img src='{{img_found}}' style="width: 800px">
            <br>
            <h3 id="format">Password Format repartition</h3>
            <table>
                <thead>
                    <tr>
                        <th scope="col">Format</th>
                        <th scope="col">Count</th>
                    </tr>
                </thead>
                <tbody>
                    {% for format,count in format.items() %}
                    <tr>
                        <td>{{format}}</td>
                        <td>{{count}}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <br>
            <img src='{{img_format}}' style="width: 800px">
            <br>
            <h3 id="length">Password Length repartition</h3>
            <table>
                <thead>
                    <tr>
                        <th scope="col">Length</th>
                        <th scope="col">Count</th>
                    </tr>
                </thead>
                <tbody>
                    {% for top,count in length.items() %}
                    <tr>
                        <td>{{top}}</td>
                        <td>{{count}}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <br>
            <div class="crop-container">
                <img src='{{img_length}}' style="width: 800px">
            </div>
            <br>
            <h3 id="most">Top 10 Most used passwords</h3>
            <table>
                <thead>
                    <tr>
                        <th scope="col">Password</th>
                        <th scope="col">Count</th>
                    </tr>
                </thead>
                <tbody>
                    {% for top,count in most.items() %}
                    <tr>
                        <td>{{top}}</td>
                        <td>{{count}}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <br>
            <div class="crop-container">
                <img src='{{img_most}}' style="width: 800px">
            </div>
            <br>
            <br>
            <h3 id="baseword">Top 10 Most used basewords</h3>
            <table>
                <thead>
                    <tr>
                        <th scope="col">Password</th>
                        <th scope="col">Count</th>
                    </tr>
                </thead>
                <tbody>
                    {% for top,count in baseword.items() %}
                    <tr>
                        <td>{{top}}</td>
                        <td>{{count}}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <br>
            <div class="crop-container">
                <img src='{{img_baseword}}' style="width: 800px">
            </div>
            <br>
            <h3 id="mask">Top 10 Most used masks</h3>
            <table>
                <thead>
                    <tr>
                        <th scope="col">Masks</th>
                        <th scope="col">Count</th>
                        <th scope="col">Percent</th>
                    </tr>
                </thead>
                <tbody>
                    {% for top,count in masks.items() %}
                    <tr>
                        <td>{{top}}</td>
                        <td>{{count}}</td>
                        <td>{{ '%.2f'| format(count/cracked*100) }}%</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <br>
            <p>Legend: d = digit, l = lowercase, U = uppercase, $ = special</p>
            <br>
            {% if img_history != '' %}
                <h3 id="history">Users with similar password pattern along history</h3>
                <br>
                <div class="crop-container">
                <img src='{{img_history}}' style="width: 800px">
                </div>
                <br>
            {% endif %}
            <span id=footer>Report generated with <a href="https://github.com/Orange-Cyberdefense/graphcat">https://github.com/Orange-Cyberdefense/graphcat</a>, a tool by Orange Cyberdefense.</span>         
    </body>
</html>
'''

class Secret:
    def __init__(self, nthash: str, cleartext: str = None):
        self.nthash = nthash

        self.cleartext = cleartext
        self.cracked = (cleartext is not None)

    def define_cleartext(self, cleartext):
        self.cracked = True
        self.cleartext = cleartext

class User:
    def __init__(self, username: str, nthash: str, cleartext: str = None):
        self.username = username

        self.secret = Secret(nthash, cleartext)
        self.cracked = (cleartext is not None)

        self.history = None

    def add_into_history(self, index: int, nthash: str, cleartext:str = None) -> None:
        if self.history is None:
            self.history = dict()
        
        self.history[index]=Secret(nthash, cleartext)

    def define_cleartext(self, cleartext: str) -> None:
        self.cracked = True
        self.secret.define_cleartext(cleartext)

class GraphCat:
    def __init__(self, options):
        self.options = options

        self.timestamp = calendar.timegm(time.gmtime())
        self.potfile = None
        self.hashes = None
        self.outputdir = '.'
        if options.output_dir is not None:
            self.outputdir = options.output_dir
            if not os.path.isdir(self.outputdir):
                os.makedirs(self.outputdir, exist_ok=True)

        print('[-] Parsing potfile')
        if options.potfile is not None:
            arr = dict()
            with open(options.potfile, 'r') as lines:
                for line in lines:
                    l = line.rstrip('\n')
                    if ':' in l:
                        l = l.split(':',1)
                        if options.john:
                            if '$NT$' in l[0]:
                                l[0] = l[0].replace('$NT$','')
                            else:
                                continue
                        arr[l[0].lower()]=l[1]
                self.potfile = arr
        if len(self.potfile) == 0:
            print('[!] No entry in potfile. Exiting...')
            sys.exit(1)
        print('[-] %s entries in potfile' % len(self.potfile))

        print('[-] Parsing hashfile')
        if options.hashfile is not None:
            
            with open(options.hashfile, 'r') as lines:
                if options.format in ['1','2']:
                    self.hashes = [line.rstrip('\n') for line in lines ]
                elif options.format == '3':
                    self.hashes = [line.rstrip('\n').split(':::')[0] for line in lines 
                    if '$:' not in line and '$_history' not in line and ':::' in line]
                else:
                    print('[!] Unknown format')
                    sys.exit(1)
        if len(self.hashes) == 0:
            print('[!] No entry in hashfile. Exiting...')
            sys.exit(1)
        print('[-] %s entries in hashfile' % len(self.hashes))

        self._users = None
        self._cracked_users = None
        self._user_and_nt_dict = None
        self._all_nt_hash = None

    def gen_stat(self) -> Dict:
        print('[-] Generating graphs...')

        dirpath = tempfile.mkdtemp()
        
        # Pie N°1 : Cracked stats

        total_user = len(self.all_nt_hash)

        found = dict()

        if len(self.cracked_users) < 1 :
            print('[!] Not user cracked ! Exiting...')
            sys.exit(0)

        found['Recovered'] = len(self.cracked_users)
        found['Not recovered'] = total_user - len(self.cracked_users)

        cracked_pct = str(round(((int(found['Recovered']) / total_user) * 100), 2))

        plt.clf()
        plt.figure(figsize=[15, 7])
        text_prop = {'fontsize':'x-large', 'fontweight':'heavy', 'color':'black', 'fontsize': 20}

        plt.pie(found.values(),
                wedgeprops={'edgecolor':'White','linewidth': 5,'antialiased': True},
                textprops=text_prop,
                colors = ['#DC1215', '#07C136'],
                startangle=90,
                autopct='%.1f%%',
                pctdistance=1.3,
                )
        
        plt.legend(labels=found.keys(), loc='best', 
           bbox_to_anchor=(0.,0.2), ncol=1, fontsize=16)

        centre_circle = plt.Circle((0, 0), 0.60, fc='white')
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)

        plt.savefig(os.path.join(dirpath,'cracked.png'), dpi=118)
        if self.options.export_charts:
            print('[-] Cracked charts available at cracked.png')
            plt.savefig(os.path.join(self.outputdir,'cracked.png'), dpi=118)

        # Pie N°2 : Format

        format = dict()

        format['Empty'] = len([e[0] for e in self.cracked_users.items() if e[1] == ''])
        format['Numeric'] = len([e[0] for e in self.cracked_users.items() if re.match('^[0-9]+$',e[1])])
        format['Alpha'] = len([e[0] for e in self.cracked_users.items() if re.match('^[a-zA-Z]+$',e[1])])
        format['Alpha + Numeric'] = len([e[0] for e in self.cracked_users.items() if re.match('^(?=[a-zA-Z0-9]*[0-9])(?=[a-zA-Z0-9]*[a-z])(?=[a-zA-Z0-9]*[A-Z])[a-zA-Z0-9]+$',e[1])])
        format['Alpha + Special'] = len([e[0] for e in self.cracked_users.items() if re.match('^(?=[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[a-z])(?=[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[A-Z])(?=[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?])[a-zA-Z!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]+$',e[1])])
        format['Numeric + Special'] = len([e[0] for e in self.cracked_users.items() if re.match('^(?=[0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[0-9])(?=[0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?])[0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]+$',e[1])])
        format['Alpha + Numeric + Special'] = len([e[0] for e in self.cracked_users.items() if re.match('^(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[0-9])(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[a-z])(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[A-Z])(?=[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?])[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]+$',e[1])])

        else_format = 0 # Merging every format with less than 1% into 'Other' category 
        for val in format.values(): 
            if val < (found['Recovered']/100):
                else_format += val

        tmp_format = {f'{key}: {val}':val for key, val in format.items() if val > 0 and val > (found['Recovered']/100)}
        if else_format > 0:
            tmp_format[f'Other: {else_format}'] = else_format
        
        plt.clf()
        plt.figure(figsize=[15, 7])
        text_prop = {'fontsize':'x-large', 'fontweight':'heavy', 'color':'black', 'fontsize': 20}
        
        plt.pie(tmp_format.values(),
                wedgeprops={'edgecolor':'White','linewidth': 5,'antialiased': True},
                textprops=text_prop,
                )
        
        plt.legend(labels=tmp_format.keys(), loc='best', 
           bbox_to_anchor=(0.,0.6), ncol=1, fontsize=16)

        centre_circle = plt.Circle((0, 0), 0.60, fc='white')
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)

        plt.savefig(os.path.join(dirpath,'format.png'), dpi=118)
        if self.options.export_charts:
            print('[-] Password format repartition available at format.png')
            plt.savefig(os.path.join(self.outputdir,'format.png'), dpi=118)

        # Pie N°3 : Length repartition

        longueur = dict()

        longueur['0-5'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{0,5}$',e[1])])
        longueur['6'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{6}$',e[1])])
        longueur['7'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{7}$',e[1])])
        longueur['8'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{8}$',e[1])])
        longueur['9'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{9}$',e[1])])
        longueur['10'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{10}$',e[1])])
        longueur['11'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{11}$',e[1])])
        longueur['12'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{12}$',e[1])])
        longueur['13'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{13}$',e[1])])
        longueur['14'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{14}$',e[1])])
        longueur['15+'] = len([e[0] for e in self.cracked_users.items() if re.match('^.{15,}$',e[1])])

        longueur_max = max(longueur.values())

        plt.clf()
        x = longueur.keys()
        y = list(longueur.values())
        plt.figure(figsize=[15, 7])
        plt.bar(x,y,  color='#3563EC', edgecolor='white')
        plt.xlabel('Length', fontsize=20)
        plt.ylabel("Count", fontsize=20)
        plt.rc('axes', titlesize=20)
        plt.rc('font', size=15)
        plt.xticks(fontsize=15)
        plt.yticks(fontsize=15)
        for i in range(len(x)):
            plt.text(i, y[i]+(longueur_max/100*1.5), y[i], ha = 'center')
        plt.savefig(os.path.join(dirpath,'length.png'), dpi=118)
        if self.options.export_charts:
            print('[-] Password length repartition available at length.png')
            plt.savefig(os.path.join(self.outputdir,'length.png'), dpi=118)

        # Pie N°4 and N°5 : Top 10 most cracked and Top 10 basewords

        c = Counter()
        c2 = Counter()
        c3 = Counter()
        for password in self.cracked_users.values():
            for i in re.findall('[a-zA-Z]{4,20}', password):
                c2[i] += 1
            if password == '':
                password = '[VIDE]'
            c[password] += 1
            c3[self.gen_mask(password)] +=1
        
        most = dict()
        for most_common in c.most_common(10):
            most[most_common[0]] = most_common[1]

        most_max = max(most.values())

        most = {key:val for key, val in most.items() if val >1}

        plt.clf()
        x = [label.replace('$$','\\$\\$') for label in most.keys()]
        y = list(most.values())
        plt.figure(figsize=[15, 10])
        plt.bar(x,y, color='#3563EC', edgecolor='white')
        plt.ylabel("Count", fontsize=20)
        plt.xticks(rotation=23)
        for i in range(len(x)):
            plt.text(i, y[i]+(most_max/100*1.5), y[i], ha = 'center')
        plt.savefig(os.path.join(dirpath,'most.png'), dpi=118)
        if self.options.export_charts:
            print('[-] Top10 most cracked password at most.png')
            plt.savefig(os.path.join(self.outputdir,'most.png'), dpi=118)

        basewords = dict()
        for key, value in c2.most_common(10):
            basewords[key] = value

        baseword_max = max(basewords.values())

        basewords = {key:val for key, val in basewords.items() if val >1}
        plt.clf()
        x = basewords.keys()
        y = list(basewords.values())
        plt.figure(figsize=[15, 10])
        plt.bar(x,y, color='#3563EC', edgecolor='white')
        plt.ylabel("Count",  fontsize=20)
        plt.xticks(rotation=23)
         
        for i in range(len(x)):
            plt.text(i, y[i]+(baseword_max/100*1.5), y[i], ha = 'center')
        plt.savefig(os.path.join(dirpath,'basewords.png'), dpi=118)
        if self.options.export_charts:
            print('[-] Top10 basewords at basewords.png')
            plt.savefig(os.path.join(self.outputdir,'basewords.png'), dpi=118)

        common_masks = dict()
        for key, value in c3.most_common(10):
            common_masks[key] = value

        # Chart N°7 Password same as in password history

        history_reuse = self.analyze_history()
        if history_reuse > 0:
            plt.clf()
            plt.figure(figsize=[15, 7])
            text_prop = {'fontsize':'x-large', 'fontweight':'heavy', 'color':'black', 'fontsize': 20}
            plt.pie([history_reuse, len(self.cracked_users.values()) - history_reuse], 
                    wedgeprops={'edgecolor':'White','linewidth': 5,'antialiased': True},
                    textprops=text_prop,
                    colors = ['#DC1215', '#07C136'],
                    startangle=90,
                    autopct='%.1f%%',
                    pctdistance=1.3,
                    )

            plt.legend(labels=['Users with similar password \npattern along history', 'Users without similar password \npattern along history'], loc='best', 
            bbox_to_anchor=(0.1,0.2), ncol=1, fontsize=16)

            centre_circle = plt.Circle((0, 0), 0.60, fc='white')
            fig = plt.gcf()
            fig.gca().add_artist(centre_circle)

            plt.savefig(os.path.join(dirpath,'history.png'), dpi=118)
            if self.options.export_charts:
                print('[-] History analysis at history.png')
                plt.savefig(os.path.join(self.outputdir,'history.png'), dpi=118)
            
        # Generate pdf report based on htlm template
        print('[-] Generating report...')

        with open(os.path.join(dirpath, 'template.html'), 'w') as template:
            template.write(TEMPLATE)

        env = Environment(loader=FileSystemLoader(dirpath))

        template = env.get_template('template.html')

        html = template.render(page_title_text='Password Cracking Report',
                            title_text='Password Cracking Report',
                            total_user = total_user,
                            cracked = found['Recovered'],
                            not_cracked = found['Not recovered'],
                            cracked_pct = cracked_pct,
                            format = format,
                            length = longueur,
                            most = most,
                            baseword = basewords,
                            masks = common_masks,
                            img_found = os.path.join(dirpath,'cracked.png'),
                            img_format = os.path.join(dirpath,'format.png'),
                            img_length = os.path.join(dirpath,'length.png'),
                            img_most = os.path.join(dirpath,'most.png'),
                            img_baseword = os.path.join(dirpath,'basewords.png'),
                            img_masks =  os.path.join(dirpath,'masks.png'),
                            img_history = os.path.join(dirpath,'history.png') if history_reuse > 0 else '',
                            )

        with open(os.path.join(dirpath,'report.html'), 'w') as f:
            f.write(html)  

        css = CSS(string='''
            @page {size: A4; margin: 1cm; @bottom-right {
                font-size: 10px;
                content: counter(page) " / " counter(pages);
                margin: 10px 10px 25px 10px;
            }} 
            th, td {border: 1px solid black;}
            img {width: 100%}
            .crop-container {overflow: hidden;}
            .crop-container img {margin-left: -50px;}
            h1 {text-align: center;font-size:30px;}
            h3 {font-size:24px;}
            table {width: 85%; border-collapse: collapse; margin-right: auto;}
            table,th,td {border: 1px solid black;}
            thead {background-color: #3563EC;color: #ffffff; font-size: 18px;}
            th {text-align: center;height: 50px;}
            td {font-size: 16px; text-align: left;padding: 5px; vertical-align: center;}
            @media print {h3 {page-break-before: always;}}
            @font-face {
            font-family: 'Titillium Web';
            font-style: normal;
            font-weight: 300;
            src: local('Titillium Web Light'), local('TitilliumWeb-Light');
            }
            *, div {font-family: 'Titillium Web';}
            #footer {font-size:8px;}
            ''')

        filename = "graphcat_%s.pdf" % self.timestamp

        HTML(os.path.join(dirpath,'report.html')).write_pdf(os.path.join(self.outputdir,filename), stylesheets=[css], optimize_size=('fonts', 'images'))
        
        # Cleanup

        shutil.rmtree(dirpath)
        print('[-] Report available at %s' % filename)

    def isNaN(self,num):
        return num!= num

    def gen_mask(self, password) -> str:
        mask = ""
        for letter in password:
            if letter in string.digits:
                mask += 'd'
            elif letter in string.ascii_lowercase:
                mask += 'l'
            elif letter in string.ascii_uppercase:
                mask += 'U'
            else:
                mask += '$'
        return mask
    
    def analyze_words(self, word1, word2):
        max_chain_similarity = 0
        similarity = 0
        for li in difflib.ndiff(word1, word2):
                    if li[0] == ' ':
                        similarity += 1
                    else:
                        similarity = 0
                    if similarity > max_chain_similarity:
                        max_chain_similarity = similarity
        return max_chain_similarity

    def analyze_history(self):
        pass_reuse_counter = 0
        for user in [user for user in self.users.values() if user.cracked]:
            if user.history is None:
                continue
            for hist in [hist for hist in user.history.values() if hist.cracked]:
                similitudes_len = self.analyze_words(hist.cleartext, user.secret.cleartext)
                if (similitudes_len >= 5) or (similitudes_len > len(user.secret.cleartext)-3) : # nearly same password (3 chars diff), or 5+ same chars in a row
                    pass_reuse_counter += 1
                    break
        return pass_reuse_counter

    def parse_ntds_line(self, line):
        elements = line.split(':')
        return elements[0], elements[3].lower() 

    @property
    def users(self) -> Dict:
        if self._users is not None:
            return self._users
        
        users = dict()
        userhist_lines = list()

        if options.format == '1':
            i = 0
            for hash in self.hashes:
                cleartext = None
                if hash in self.potfile.keys():
                    hash = hash.lower()
                    cleartext = self.potfile[hash]
                users[f'user_{i}']=User(f'user_{i}', hash, cleartext)
                i += 1
        elif options.format == '2':
            for line in self.hashes:
                username, hash = line.split(':')
                hash = hash.lower()
                cleartext = None
                if hash in self.potfile.keys():
                    cleartext = self.potfile[hash]
                users[username]=User(username, hash, cleartext)
        elif options.format == '3':
            for line in self.hashes:
                if '_history' in line:
                    userhist_lines.append(line)
                else:
                    username, nthash = self.parse_ntds_line(line)
                    cleartext = None
                    if nthash in self.potfile.keys():
                        cleartext = self.potfile[nthash]
                    users[username] = User(username, nthash, cleartext)
                    
            for userhist_line in userhist_lines:
                username, nthash = self.parse_ntds_line(userhist_line)
                user, index = username.split('_history')
                cleartext = None
                if nthash in self.potfile.keys():
                    cleartext = self.potfile[nthash]
                users[user].add_into_history(index, nthash, cleartext)

        self._users = users
        return self._users

    @property
    def cracked_users(self) -> Dict:
        if self._cracked_users is not None:
            return self._cracked_users
            
        self._cracked_users = {user.username:user.secret.cleartext for user in self.users.values() if user.cracked}
        return self._cracked_users

    @property
    def all_nt_hash(self) -> List:
        if self._all_nt_hash is not None:
            return self._all_nt_hash
        self._all_nt_hash = [user.secret.nthash for user in self.users.values()]
        return self._all_nt_hash

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(
        description="Password Cracking Graph Reporting", add_help=True
    )

    parser.add_argument(
        "-potfile",
        action="store",
        required=True,
        metavar="hashcat.potfile",
        help="Hashcat Potfile",
    )

    parser.add_argument(
        "-hashfile",
        action="store",
        required=True,
        metavar="hashfile.txt",
        help="File containing hashes (one per line)",
    )

    parser.add_argument("-john", action="store_true", help="John potfile")
    parser.add_argument("-format", action="store", default="3", help="hashfile format (default 3): 1 for hash; 2 for username:hash; 3 for secretsdump (username:uid:lm:ntlm)")
    parser.add_argument("-export-charts", action="store_true", help="Output also charts in png")
    parser.add_argument("-output-dir", action="store", help="Output directory")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    options = parser.parse_args()

    try:
        executor = GraphCat(options)
        executor.gen_stat()
    except Exception as e:
        if options.debug:
            import traceback
            traceback.print_exc()
        print('ERROR: %s' % str(e))