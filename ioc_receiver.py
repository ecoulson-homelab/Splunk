"""
The IOC Receiver module is made up of six methods.
three of which pull their respective IOCs and three corresponding methods which format the IOCs in
a way that Splunk ES' Threat Intelligence Framework can accept.
For example, there are two methods pertaining to the pull, and formatting of IP addresses
"""

from datetime import datetime, timedelta
import os
import re
import time
import requests
import splunkUtil


class IOCReceiver:
    def __init__(self):

        self.ds_key = os.environ.get("dsKey")
        self.ds_secret = os.environ.get("dsSecret")
        self.indicator_endpoint = os.environ.get("indicatorEndpoint")
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;charset=UTF-8"
        }

        self.splunk_util = splunkUtil.splunkUploader()

        #Get the time parameters for the last hour
        self.one_hour_ago = datetime.now().replace(microsecond=0) - timedelta(hours=1)
        self.one_hour_ago = self.one_hour_ago.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.today = datetime.now().replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

        # self.source_types contains the IOC sourcetypes as described here:
        # https://portal-digitalshadows.com/learn/api/latest/indicators/post/%2Findicators%2Ffind
        self.source_types = [
              "OPEN_PHISH"
            , "PHISHTANK"
            , "ALIENVAULT"
            , "INTEL_INCIDENT"
            , "APT_REPORT"
            , "THREAT_PROFILE"
            , "URLHAUS"
            ]

        # self.type is used later in the Splunk request, as a way of changing the file name once it's uploaded, respective to the current sourceType.
        self.type = ""

    def get_hashes(self):

        """
        get_hashes requests SHA-256 indicators from the indicator endpoint.
        If more hash types are required you can add them by changing the 'types' field
        in the fstring from:
        'types': ['SHA256']
        to:
        'types': ['SHA256', 'SHA1', 'MD5'] etc.

        To see the full list of available IOCs see the documentation:
        https://portal-digitalshadows.com/learn/api/latest/indicators/post/%2Findicators%2Ffind
        """

        # ip_list is a concatenated string of all ips found on the current sourceType.
        hash_list = ""

        # Loop through the sourceTypes list, and make an API request for each source type.
        for i in self.source_types:
            try:
                filters = (
                    f"{{ 'filter': {{'actorThreats': [], 'lastUpdated': '{self.one_hour_ago}/{self.today}', "
                    f"'malwareThreats': [], 'types': ['SHA256'],'sourceType': '{i}' }}, 'pagination': {{ 'offset': 0, 'size':500 }},"
                    f"'sort': {{ 'direction': 'DESCENDING', 'property': 'updated' }} }}"
                )

                response = requests.post(url=self.indicator_endpoint, headers=self.headers, auth=(self.ds_key, self.ds_secret), data=filters)
                print(response.text)
                if response.status_code == 200:
                    # Extract only the IP addresses, as Splunk can't make use of the rest of the information anyway.
                    hashes = re.findall(r'(?:[a-f0-9]{64})', response.text)
                    hashes = re.sub(r'[\'\[\]]', "", str(hashes))
                    hash_list += hashes
                    self.format_hashes(hash_list)
                    self.type = i

            except requests.exceptions.ConnectionError:
                print("error ", response.status_code, " ", response.text)

    def get_ips(self):

        """
        get_ips requests IPv4 indicators from the indicator endpoint.
        
        IPv6 indicators are also available, though they seem to come
        predominately from the URL indicator type. See the get_domains
        method for further clarity
        
        Full list of available IOCs see the documentation:
        https://portal-digitalshadows.com/learn/api/latest/indicators/post/%2Findicators%2Ffind
        """

        # ip_list is a concatenated string of all ips found on the current sourceType.
        ip_list = ""

        # Loop through the sourceTypes list, and make an API request for each source type.
        for i in self.source_types:
            try:
                filters = (
                    f"{{ 'filter': {{'actorThreats': [], 'lastUpdated': '{self.one_hour_ago}/{self.today}', "
                    f"'malwareThreats': [], 'types': ['IP'],'sourceType': '{i}' }}, 'pagination': {{ 'offset': 0, 'size':500 }},"
                    f"'sort': {{ 'direction': 'DESCENDING', 'property': 'updated' }} }}"
                )

                response = requests.post(url=self.indicator_endpoint, headers=self.headers, auth=(self.ds_key, self.ds_secret), data=filters)
                print(response.text)
                if response.status_code == 200:
                    # Extract only the IP addresses, as Splunk can't make use of the rest of the information anyway.
                    ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', response.text)
                    ips = re.sub(r'[\'\[\]]', "", str(ips))

                    ip_list += ips
                    self.format_ips(ip_list)
                    self.type = i

                    # Sleep for 10 seconds before continuing the loop - allows HTTPS requests to go through, avoids contention etc.
                    # Need to rework this.
                    time.sleep(10)
                elif response.status_code != 200:
                    raise requests.exceptions.ConnectionError

            except requests.exceptions.ConnectionError:
                print("error ", response.status_code, " ", response.text)

    def get_domains(self):

        """
        get_domains requests a mixture of indicators including IPv4, IPv6, and 
        domains from the indicator endpoint.
        
        The indicators can contain port numbers, as well as URI / resource paths.
        
        Full list of available IOCs see the documentation:
        https://portal-digitalshadows.com/learn/api/latest/indicators/post/%2Findicators%2Ffind
        """

        domain_list = ""
        # Loop through the sourceTypes list, and make an API request for each source type.
        for i in self.source_types:
            try:
                filters = (
                    f"{{ 'filter': {{'actorThreats': [], 'lastUpdated': '{self.one_hour_ago}/{self.today}', "
                    f"'malwareThreats': [], 'types': ['URL'],'sourceType': '{i}' }}, 'pagination': {{ 'offset': 0, 'size':500 }},"
                    f"'sort': {{ 'direction': 'DESCENDING', 'property': 'updated' }} }}"
                )

                response = requests.post(url=self.indicator_endpoint, headers=self.headers, auth=(self.ds_key, self.ds_secret), data=filters)

                if response.status_code == 200:
                    # As the indicator endpoint can return many 'types' of URL including IP addresses, multiple regex strings are needed to capture them all.
                    domains = re.findall(
                                         # Match either HTTP or HTTPS as both are likely to occur in the responses.
                                         r'"value":"\b((?:https?://)?'
                                         # Match on any domains.
                                         r'(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})'
                                         # Match on any IPv4 addresses.
                                         r'|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
                                         # Match on IPv6 addresses if present.
                                         r'|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))'
                                         # Match port numbers if present.
                                         r'(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?'
                                         # Finally match on the resource path.
                                         r'(?:/[\w\.-]*)*/?)\b', response.text)

                    domains = re.sub(r'"value":', "", str(domains))

                    print(domains)

                    domain_list += domains
                    self.format_domains(domain_list)
                    self.type = i

                    time.sleep(10)

                elif response.status_code != 200:
                    raise requests.exceptions.ConnectionError

            except requests.exceptions.ConnectionError:
                print("error ", response.status_code, " ", response.text)

    def format_hashes(self, hash_list):

        """
        format_hashes takes the hashes taken from get_hashes and creates
        a list in a splunk-ready format. It should be formatted something along the lines of
        string,indicator,weight where weight represents the signifigance with which Enterprise
        Security will treat any hits. 
        
        A higher weight means greater significance if a hit were to occur.
        
        I.e. an indicator with a weight of 100 will have far greater importance put upon it
        by Splunk Enterprise Security than an indicator with a weight of 1.

        By default this method gives a weight value of 50; to change this, you can increase
        or decrease the numeric string in the 'weight' variable below.
        e.g. 
        weight = ",50"
        weight = ",10"
        weight = ",72"

        See Splunk's documentation on what is considered acceptable formatting
        for the Threat Intelligence Framework:
        https://docs.splunk.com/Documentation/ES/latest/Admin/Supportedthreatinteltypes
        """


        file_header = "description,file_hash,weight"
        hash_list = hash_list.split(sep=",")
        description = "SHA256_IOCS,"
        weight = ",50"

        splunk_list = []
        for i in hash_list:
            splunk_list.append(description + i + weight)
        splunk_list = "\n".join(splunk_list)
        splunk_list = re.sub(r'[\'\[\] ]', "", splunk_list)

        final_list = f'{str(file_header)}\n{splunk_list}'

        self.splunk_util.base64Encode(final_list=final_list)

    def format_ips(self, ip_list):

        """
        format_ips takes the IPv4 addresses taken from get_ips and creates
        a list in a splunk-ready format. It should be formatted something along the lines of
        string,indicator,weight where weight represents the signifigance with which Enterprise
        Security will treat any hits. 
        
        A higher weight means greater significance if a hit were to occur.
        
        I.e. an indicator with a weight of 100 will have far greater importance put upon it
        by Splunk Enterprise Security than an indicator with a weight of 1.

        By default this method gives a weight value of 50; to change this, you can increase
        or decrease the numeric string in the 'weight' variable below.
        e.g. 
        weight = ",50"
        weight = ",10"
        weight = ",72"

        See Splunk's documentation on what is considered acceptable formatting
        for the Threat Intelligence Framework:
        https://docs.splunk.com/Documentation/ES/latest/Admin/Supportedthreatinteltypes
        """

        # Splunk requires the header format: description,ip,weight
        file_header = "description,ip,weight"
        ip_list = ip_list.split(sep=",")
        description = "IP_IOCS,"
        weight = ",50"

        # Concatenate in Splunk-friendly format (description,ip,weight)
        splunk_list = []
        for i in ip_list:
            splunk_list.append(description + i + weight)
        splunk_list = "\n".join(splunk_list)
        splunk_list = re.sub(r'[\'\[\] ]', "", splunk_list)

        final_list = f"{str(file_header)}\n{splunk_list}"
        # self.base64Encode(final_list)
        self.splunk_util.base64Encode(final_list=final_list)

    def format_domains(self, domain_list):

        """
        format_domains takes the miriad of potential indicators taken from get_domains
        and creates a list in a splunk-ready format. It should be formatted something
        along the lines of string,indicator,weight where weight represents the
        signifigance with which Enterprise Security will treat any hits. 
        
        A higher weight means greater significance if a hit were to occur.
        
        I.e. an indicator with a weight of 100 will have far greater importance put upon it
        by Splunk Enterprise Security than an indicator with a weight of 1.

        By default this method gives a weight value of 50; to change this, you can increase
        or decrease the numeric string in the 'weight' variable below.
        e.g. 
        weight = ",50"
        weight = ",10"
        weight = ",72"

        See Splunk's documentation on what is considered acceptable formatting
        for the Threat Intelligence Framework:
        https://docs.splunk.com/Documentation/ES/latest/Admin/Supportedthreatinteltypes
        """

        # Splunk requires the header format: description,http_referrer,http_user_agent,url,weight
        # https://docs.splunk.com/Documentation/ES/6.6.2/Admin/Supportedthreatinteltypes
        file_header = "description,url,weight"
        domain_list = domain_list.split(sep=",")
        description = "DOMAIN_IOCS,"
        weight = ",50"

        # Concatenate in Splunk-friendly format (description,domain,weight)
        splunk_list = []
        for i in domain_list:
            splunk_list.append(description + i + weight)
        splunk_list = '\n'.join(splunk_list)
        splunk_list = re.sub(r'[\'\"\[\] ]', "", splunk_list)

        final_list = f"{str(file_header)}\n{splunk_list}"
        self.splunk_util.base64Encode(final_list=final_list)
