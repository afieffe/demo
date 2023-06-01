import os, argparse,logging
import xlsxwriter
from laceworksdk import LaceworkClient
from datetime import datetime, timedelta, timezone
import re
import pandas as pd
import concurrent.futures
from string import Template
import copy
import json



SEVERITY=pd.DataFrame( {"SEVERITY" : [1,2,3,4,5] , "SEVERITY_S" :["critical", "high", "medium" ,"low","info"]} )

MAX_THREADS=8

VULN_META=['vulnId','fixInfo.fix_available','featureKey.name','featureKey.namespace','severity']
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

EXT_LIST={ 'namespace': 'featureKey' ,
        'name' : 'featureKey',
        'namespace' : 'featureKey',
        'package_active' : 'featureKey',
        'version_installed' : 'featureKey',
        'fix_available': 'fixInfo',
        'fixed_version' : 'fixInfo',
        'hostname': 'evalCtx'}

class lw_vulnerabilities:
    def __init__(self,args,lw_client):
        self.lw_client = lw_client
        self.args = args
        self.current = datetime.now(timezone.utc)
        self.start_time = (self.current - timedelta(hours=0, days=args.days)).strftime(ISO_FORMAT)
        self.end_time = self.current.strftime(ISO_FORMAT)
        self.lw_accounts = self.get_subaccount_list()

        #self.cont_vulnerabilities=self.get_all_containers_vulnerabilities()
        self.vulnerabilities=self.get_all_vulnerabilities()
        #self.inventory = self.get_inventory_diff('AwsCompliance')



    def get_containers_vulnerabilities(self,sub_account):
        logging.info(f'Getting container vulnerabilities, lw org:{sub_account} ')
        lw_client=copy.deepcopy(self.lw_client)
        lw_client.set_subaccount(sub_account)
        vulns=[]
        query = {
        "timeFilter": {
            "startTime": self.start_time,
            "endTime": self.end_time
        },
        "filters": [

            { "field": "severity", "expression": "in", "values": [ "Critical", "High", "Medium" ,"Low","Info"] }
        ],
        "returns": [
            "imageId",
            "evalCtx",
            "fixInfo",
            "featureKey",
            "severity",
            "status",
            "vulnId",
            "startTime"

        ]
        }

        try:
            vulns_conts=lw_client.vulnerabilities.containers.search(json=query)
            for h in vulns_conts:
                vulns=vulns+h['data']
            for i, d in enumerate(vulns):
                 vulns[i]['LW_ORG']=sub_account
        except Exception as e:
            logging.error(f'Error Getting vulnerabilities for  lw org: {sub_account} {e}')
        lw_client=None
        return (vulns,"vulns")

    def get_active_containers(self,sub_account):
        logging.info(f'Getting active container, lw org:{sub_account} ')
        lw_client=copy.deepcopy(self.lw_client)
        lw_client.set_subaccount(sub_account)
        containers=[]

        query = {
        "timeFilter": {
            "startTime": self.start_time,
            "endTime": self.end_time
        },
        "returns": [
            "imageId",
            "containerName",
            "mid",
            "propsContainer"
        ]
        }
        try:
            cont_w=lw_client.entities.containers.search(json=query)
            for h in cont_w:
                containers=containers+h["data"]
            for i, d in enumerate(containers):
                 containers[i]['LW_ORG']=sub_account
        except Exception as e:
                logging.error(f'Error Getting containers for  lw org: {sub_account} {e}')
        return (containers,"containers")



    def get_all_containers_vulnerabilities(self):
        futures=[]
        vulns=[]
        conts=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            for sub_account in self.lw_accounts:
                futures.append(pool.submit(self.get_containers_vulnerabilities,sub_account))
                futures.append(pool.submit(self.get_active_containers,sub_account))
            for future in concurrent.futures.as_completed(futures):
                results,res_type=future.result()
                if res_type=='vulns':
                    if len(future.result()) > 0:
                        vulns= vulns+results
                if res_type=="containers":
                    if len(future.result()) > 0:
                        conts = conts+results

        if len(vulns) > 0 and len(conts) > 0:
            return self.format_cont_vulnerabilities(vulns,conts)
        else:
            return None


    def format_cont_vulnerabilities(self,vulns,conts):
        vulns_df=pd.json_normalize(vulns,errors='ignore')

        cont_df=pd.json_normalize(conts,errors='ignore')
        cols = ['containerName', 'imageId', 'mid', 'propsContainer.CONTAINER_START_TIME']
        cont_df['cont_u'] = cont_df[cols].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)


        cont_df=cont_df.groupby(['imageId']).agg(active_containers=('cont_u','nunique'))
        vulns_df['scan_time']=pd.to_datetime(vulns_df['startTime']).dt.tz_localize(None)
        group=['imageId','vulnId','fixInfo.fix_available','featureKey.name','featureKey.namespace','severity','evalCtx.image_info.registry','evalCtx.image_info.repo','evalCtx.image_info.tags','LW_ORG']
        vulns_df['evalCtx.image_info.tags'] = [','.join(map(str, l)) for l in vulns_df['evalCtx.image_info.tags']]
        vulns_df=vulns_df.groupby(group).agg(first_seen=('scan_time','min'), last_seen=('scan_time','max'))
        vulns_df=vulns_df.reset_index()

        vuln_cont=pd.merge(vulns_df,cont_df.reset_index(),on=['imageId'],how='left')
        vuln_cont=vuln_cont.reset_index()
        vuln_cont['active_containers'].fillna(0,inplace=True)


        return vuln_cont


    def get_host_vulnerabilities(self,sub_account):
        logging.info(f'Getting Host vulnerabilities, lw org:{sub_account} ')
        lw_client=copy.deepcopy(self.lw_client)
        lw_client.set_subaccount(sub_account)
        vulns=[]
        query = {
        "timeFilter": {
            "startTime": self.start_time,
            "endTime": self.end_time
        },
        "filters": [

            { "field": "severity", "expression": "in", "values": [ "Critical", "High", "Medium" ,"Low","Info"] }
        ],
        "returns": [
            "mid",
            "severity",
            "status",
            "vulnId",
            "machineTags",
            "evalCtx",
            "featureKey",
            "fixInfo",
            "startTime"     ]

        }
        try:
            vulns_conts=lw_client.vulnerabilities.hosts.search(json=query)
            for h in vulns_conts:
                vulns=vulns+h['data']
            for i, d in enumerate(vulns):
                 vulns[i]['LW_ORG']=sub_account
        except Exception as e:
            logging.error(f'Error Getting host vulnerabilities for  lw org: {sub_account} {e}')
        lw_client=None
        return vulns


    def format_host_vulnerabilities(self,vulns):
        vulns_df=pd.json_normalize(vulns,max_level=0,errors='ignore')
        for key in EXT_LIST.keys():
            vulns_df[key] = vulns_df.apply(lambda x: x[EXT_LIST[key]][key], axis = 1)

        vulns_df.drop(columns=['featureKey','fixInfo','evalCtx'], inplace=True)
        vulns_df['scan_time']=pd.to_datetime(vulns_df['startTime']).dt.tz_localize(None)
        group=[ 'mid', 'severity', 'vulnId',
       'LW_ORG', 'namespace', 'name', 'package_active', 'version_installed',
       'fix_available', 'fixed_version', 'hostname']
        vulns_df.sort_values(by=['scan_time'], inplace=True)
        vulns_df['machineTags'] = vulns_df['machineTags'].astype(str)
        vulns_df=vulns_df.groupby(group + ['machineTags']).agg(first_seen=('scan_time','min'), last_seen=('scan_time','max'), status=('status','last'))
        vulns_df=vulns_df.reset_index()
        vulns_df=vulns_df[group + ['first_seen', 'last_seen','machineTags']]

        return vulns_df

    def get_all_hosts_vulnerabilities(self):
        futures=[]
        vulns=[]
        conts=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.max_threads) as pool:
            for sub_account in self.lw_accounts:
                futures.append(pool.submit(self.get_host_vulnerabilities,sub_account))
            for future in concurrent.futures.as_completed(futures):
                    if len(future.result()) > 0:
                        vulns= vulns+future.result()

        if len(vulns) > 0:
            return self.format_host_vulnerabilities(vulns)
        else:
            return None

    def get_all_vulnerabilities(self):
        conts_vuln=self.get_all_containers_vulnerabilities()
        hosts_vuln=self.get_all_hosts_vulnerabilities()
        if conts_vuln is not None or hosts_vuln is not None:
            with pd.ExcelWriter( self.get_file_name_base() + ".xlsx",engine='xlsxwriter') as writer:
                    if conts_vuln is not None:
                        conts_vuln.to_excel(writer,sheet_name='containers vuln',merge_cells=False,index=False)
                        format_sheet(writer,'containers vuln',conts_vuln)
                    else:
                        logging.info(f'Container vulnerabilities list empty, lw org:{self.args.subaccount} ')
                    if hosts_vuln is not None:
                        hosts_vuln.to_excel(writer,sheet_name='hosts vuln',merge_cells=False,index=False)
                        format_sheet(writer,'hosts vuln',hosts_vuln)
                    else:
                        logging.info(f'Host vulnerabilities list empty, lw org:{self.args.subaccount} ')
        else:
            logging.info(f'No Host or Container vulnerabilities for subaccount, lw org:{self.args.subaccount} ')

        return None


    def gen_excel(self,results):
        with pd.ExcelWriter( self.get_file_name_base() + ".xlsx",engine='xlsxwriter') as writer:
            for cloud_provider in results.keys():
                for tab in results[cloud_provider].keys():
                    results[cloud_provider][tab].to_excel(writer,sheet_name=cloud_provider + " " + tab,merge_cells=False,index=False)
                    format_sheet(writer,cloud_provider + " " + tab,results[cloud_provider][tab])
        return None


    def get_file_name_base(self):
        try:
            client=re.search("^([^\.]+)",self.lw_client.user_profile.get()['data'][0]['url']).group()
        except:
            client='not-found'
        timestp=self.current.strftime('%Y-%m-%d_%H.%M.%S')
        filename=client+'_assesment_report_vulnerabilities'+ timestp

        return filename

    def get_subaccount_list(self):
        profile=self.lw_client.user_profile.get()
        sub_accounts=[]
        if self.args.subaccount:
            sub_accounts.append(self.args.subaccount)
        else:
          if profile:
            data=profile.get('data', None)
            for sub_account in  data[0]['accounts']:
                if sub_account['accountName'] not in sub_accounts:
                    sub_accounts.append(sub_account['accountName'])

        return sub_accounts


def get_col_widths(dataframe):
    # First we find the maximum length of the index column
    #idx_max = max([len(str(s)) for s in dataframe.index.values] + [len(str(dataframe.index.name))])
    # Then, we concatenate this to the max of the lengths of column name and its values for each column, left to right
    return [max([len(str(s)) for s in dataframe[col].values] + [len(col)]) for col in dataframe.columns]

def format_sheet(writer,sheet_name,df):
    workbook = writer.book
    worksheet = writer.sheets[sheet_name]
    worksheet.autofilter('A1:'+ xlsxwriter.utility.xl_col_to_name(len(df.columns)-1) + str(len(df.index)))
    header_fmt = workbook.add_format({'align': 'middle', 'bg_color': '#C6EFCE'})
    for i, width in enumerate(get_col_widths(df)):
        worksheet.set_column(i, i, width)


def main(args):
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    try:
        lw_client = LaceworkClient(
            account=args.account,
            subaccount=args.subaccount,
            api_key=args.api_key,
            api_secret=args.api_secret,
            profile=args.profile
        )
    except Exception:
        raise
    report = lw_vulnerabilities(args,lw_client)

if __name__ == '__main__':
    # Set up an argument parser
    parser = argparse.ArgumentParser(
        description=''
    )
    parser.add_argument(
        '--account',
        default=os.environ.get('LW_ACCOUNT', None),
        help='The Lacework account to use'
    )
    parser.add_argument(
        '--subaccount',
        default=os.environ.get('LW_SUBACCOUNT', None),
        help='The Lacework sub-account to use'
    )
    parser.add_argument(
        '--api-key',
        dest='api_key',
        default=os.environ.get('LW_API_KEY', None),
        help='The Lacework API key to use'
    )
    parser.add_argument(
        '--api-secret',
        dest='api_secret',
        default=os.environ.get('LW_API_SECRET', None),
        help='The Lacework API secret to use'
    )
    parser.add_argument(
        '--gcp-folders',
        dest='gcp_folders',
        nargs='*',
        default=None,
        help='The gcp folder names to filter as a list "project-a project-b"'
    )
    parser.add_argument(
        '-p', '--profile',
        default=os.environ.get('LW_PROFILE', None),
        help='The Lacework CLI profile to use'
    )
    parser.add_argument(
        '--days',
        default=os.environ.get('LOOKBACK_DAYS', 7),
        type=int,
        help='The number of days in which to search for active containers'
    )
    parser.add_argument(
        '--hours',
        default=0,
        type=int,
        help='The number of hours in which to search for active containers'
    )
    parser.add_argument(
        '--gcp-report-type',
        default=['GCP_CIS13'],
        nargs='*',
        type=str,
        help='The report type(s) to use  eg. GCP_ISO_27001_2013 GCP_HIPAA_Rev2 default (GCP_ISO_27001_2013)  available reports:\
             GCP_HIPAA,GCP_CIS,GCP_SOC,GCP_CIS12,GCP_K8S,GCP_PCI_Rev2,GCP_SOC_2,GCP_HIPAA_Rev2,GCP_ISO_27001_2013,GCP_NIST_CSF,GCP_NIST_800_53_REV4,GCP_NIST_800_171_REV2,GCP_PCI,GCP_CIS13'
    )
    parser.add_argument(
        '--azure-report-type',
        default=['AZURE_CIS_1_5'],
        type=str,
        nargs='*',
        help='The report type(s) to use a as a list eg. GCP_ISO_27001 GCP_HIPAA_Rev2 default (GCP_ISO_27001) '
    )
    parser.add_argument(
        '--aws-report-type',
        default=['LW_AWS_SEC_ADD_1_0','AWS_CIS_14'],
        type=str,
        nargs='*',
        help='The report type(s) to use a as a list eg. GCP_ISO_27001 GCP_HIPAA_Rev2 default (GCP_ISO_27001) '
    )
    parser.add_argument(
        '--max-threads',
        action='store_true',
        default=MAX_THREADS,
        help='Maximum number of threads to be used'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('LW_DEBUG', False),
        help='Enable debug logging'
    )
    args = parser.parse_args()


    main(args)