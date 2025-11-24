# This script will walk though the Security event log on Widows
# Looking for logon / logoff events to audit user activity
# Logon / logoff events are matched and the duration of the session
# is logged.
import win32evtlog
import datetime
import xmltodict
from datetime import datetime, timedelta
import pytz
from pytz import timezone

# Local time zone to convert UTC to local
LOCAL_TIMEZONE = 'America/Chicago'

# Dictionary listing active users
activeusers = {}

# Parse Windows "T" time to Python datetime format
def parse_event_time(isotime):
   normalizedtime = isotime[:isotime.find('.')]
   return datetime.strptime(normalizedtime, "%Y-%m-%dT%H:%M:%S").astimezone(timezone(LOCAL_TIMEZONE))

# Enumerate over event data to make it usable as a dictionary
def parse_event_data(event):
   data = {}
   for item in event['Event']['EventData']['Data']:
      data[item['@Name']] = item['#text']
   return data

# Process a logon event
# Add a dictionary entry for this account noting 
# relevant data for the login event
def user_logon(account, logontime, workstation, ipaddress):
   # Bypass accounts used by RDP connections
   if account[:4] != 'DWM-' and account[:5] != 'UMFD-':
      details = {}
      details['logonTime'] = logontime
      details['workstation'] = workstation
      details['IPAddress'] = ipaddress
      activeusers[account] = details

# Process a logoff event
# Match up this event with the login event to
# determine the duration of the session
def user_logoff(account, logofftime, reason):
   if account in activeusers:
      duration = activeusers[account]['logonTime'] - logofftime
      print (f'{account},{activeusers[account]['logonTime']},{logofftime},"{duration}",{activeusers[account]['workstation']},{activeusers[account]['IPAddress']},{reason}')
      activeusers.pop(account) 


# Open up the Security event log
# Query only for event ID's 4624, 4634, 4647, 4778 and 4779
channelName = "Security"
flags = win32evtlog.EvtQueryReverseDirection
evtQuery = "*[System[(EventID=4624 or EventID=4634 or EventID=4647 or EventID=4778 or EventID=4779)]]"
evtQueryTimeout = -1
evtQueryResult = win32evtlog.EvtQuery(channelName, flags, evtQuery, None)

# print the headers
print ('Account,Logon Time,Logff Time,Duration,Workstation,IP Address,Reason')

# Enumerate over the events processing logon/logoff events
while True:
   events = win32evtlog.EvtNext(evtQueryResult, 100, evtQueryTimeout, 0)
   if events:
      for event in events:
         # Convert the event message to XML so we can grab real data fields     
         xml = xmltodict.parse(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
         # Process the event data into something useful to us
         data = parse_event_data(xml)

         # Get the event ID
         EventID = xml['Event']['System']['EventID']
         # Get the event time in Python datetime format adjusted for local time.
         EventTime = parse_event_time(xml['Event']['System']['TimeCreated']['@SystemTime'])

         match EventID:
            case '4624':  # An account was successfully logged on
               if data['LogonType'] == '2':  # Interactive Login
                  user_logon(data['TargetUserName'], EventTime, data['WorkstationName'], data['IpAddress'])  
               if data['LogonType'] == '10': # Remote Interactive
                  user_logon(data['TargetUserName'], EventTime, data['WorkstationName'], data['IpAddress'])  
            case '4634': # An account was logged off
               if data['LogonType'] == '2' or data['LogonType'] == '10': 
                     user_logoff(data['TargetUserName'], EventTime, 'Logoff') 
            case '4647': # User initiated logoff
               user_logoff(data['TargetUserName'], EventTime, 'Logoff')
            case '4778': # A session was reconnected to a Window Station
               user_logon(data['AccountName'], EventTime, data['ClientName'], data['ClientAddress'])
            case '4779': # A session was disconnected from a Window Station
               user_logoff(data['AccountName'], EventTime, 'RDP Disconnect')
               
   else:
      break
