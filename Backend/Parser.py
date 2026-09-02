#The parser will take raw log data and structure it 
#for the Detection engine. 
#The parser will also update the events table to document
#all events regardless of if they set off an alert

from dataclasses import dataclass
from datetime import datetime
import json
import psycopg

conn = psycopg.connect(
    dbname="andreacruz",
    user="andreacruz",
    host="localhost",
    port=5432
)
cursor = conn.cursor()


@dataclass
class Event:
    event_id: str
    timestamp: datetime
    event_type: str
    username: str
    source_ip: str
    source_port: int
    destination_port: int
    status: str




#begin parser logic

#the parser will look at the log line by line. It will look for each atrribute of an event seperately.
#the line will be scanned to find patterns from each one. event_id is preset and so is timestamp
#begin with event_type -> username -> source_ip -> source_port -> status

# conceptually: line = event

def parse_line(instance: str) -> Event: 
    eventdata = json.loads(instance)
    #this function will make a python library from the json log data
    #from here we will assign the data in the library to each event atrribute
    event_id = "none"
    timestamp = eventdata["timestamp"]
    event_type = eventdata["event_type"]
    username = eventdata["username"]
    source_ip = eventdata["source_ip"]
    source_port = eventdata["source_port"]
    destination_port = eventdata["destination_port"]
    status = eventdata["status"]
    
    #create the event object with all of the information we gathered 
    currentEvent = Event(event_id, timestamp, event_type, username, source_ip, source_port, destination_port, status)


    eventstable = cursor.execute(
        """INSERT INTO events (event_id, timestamp, event_type, username, source_ip, source_port, destination_port, status)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            event_id,
            timestamp,
            event_type,
            username,
            source_ip,
            source_port,
            destination_port,
            status
        )
    )
    conn.commit()

    return currentEvent
# data is inserted into the events table 