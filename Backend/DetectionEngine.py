#the Detection engine will examine all of the structured log
#data passed from the parser and will use a list of rules to 
#determine if log activity is suspicious and decide to trigger
#an alert or send a 'clean' report back to the front end
#if an alert is made the detection engine will update the alerts
#table

from dataclasses import dataclass
from datetime import datetime, timedelta
from Backend.Parser import Event
import psycopg
from Backend.Parser import parse_line

conn = psycopg.connect(
    dbname="andreacruz",
    user="andreacruz",
    host="localhost",
    port=5432
)
cursor = conn.cursor()



##############################################################
port_scanning_status = False
brute_force_status = False
password_spraying_status = False
suspicious_login_status = False

def main():
    print("main function")

    #currentEvent = parse_line(instance)
    #EventDetection(currentEvent)


    #we will send all global status variables to javascript
    print("running")














################################################################


@dataclass
class Alert:
    alert_id: str
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: str
    destination_port: str | None
    description: str


########### main detection logic #################

def EventDetection(currentEvent: Event):
    if currentEvent.status == "FAIL": ##brute force  
        brute_force_status = False   
        brute_force_status = detectBruteForce(currentEvent)
        #maybe call brtueforce for a success. if brute force is detected then we can generate a success after brute force

    if currentEvent: ###password spraying
        password_spraying_status = False
        password_spraying_status = detectPasswordSpraying(currentEvent)
        #maybe here write the code that send the information to javascript if the variable is true.

    if currentEvent:###port scanning 
        port_scanning_status = False
        port_scanning_status = detectPortScanning(currentEvent)

    if currentEvent:###suspiciousLogin
        suspicious_login_activity = False
        suspicious_login_status = detectSuspiciousLogin(currentEvent)

    current_result = result_from_scan(brute_force_status, password_spraying_status, port_scanning_status, suspicious_login_status)
    return current_result

##################################################

@dataclass
class result_from_scan:
    bruteForce: bool
    passwordSpraying: bool
    portScanning: bool
    suspiciousLogin: bool



#attack detection functions

def detectSuspiciousLogin(currentEvent: Event):
    target_ip = currentEvent.source_ip
    target_username = currentEvent.username
    cursor.execute("SELECT source_ip FROM events WHERE username = %s ", (target_username,))
    results = cursor.fetchall()
    number_of_ip_used_for_username = len(results)
    if number_of_ip_used_for_username > 1:
        cursor.execute(
            """INSERT INTO alerts(alert_id, timestamp, alert_type, severity, source_ip, description)
            Values(%s, %s, %s, %s, %s, %s)""",
            (
                "4",
                datetime.now(),
                "SUSPICIOUS LOGIN ACTIVITY",
                "LOW",
                currentEvent.source_ip,
                "Login from Different IP"
            )

        )
        conn.commit()
        return True
    else:
        return

    


def detectPortScanning(currentEvent):
    destination_port = currentEvent.destination_port
    source_ip = currentEvent.source_ip
    cursor.execute("SELECT destination_port FROM events WHERE source_ip = %s" , (source_ip,) )
    results = cursor.fetchall()
    count = len(results)

    if count >= 2 :
        cursor.execute(
            """INSERT INTO alerts(alert_id, timestamp, alert_type, severity, source_ip, description)
            VALUES(%s,%s,%s,%s,%s,%s)""",
            (
                "3",
                datetime.now(),
                "PORT SCANNING",
                "MEDIUM",
                currentEvent.source_ip,
                "Port Scanning Detected"
            )
        )
        conn.commit()
        return True

    else:
        return
        


def detectPasswordSpraying(currentEvent: Event):
    target_ip = currentEvent.source_ip
    #count the number of times the source IP is found in the database
    #count the number of usernames have been associated with that ip 

    cursor.execute ("SELECT username FROM events WHERE source_ip = %s", (target_ip,))
    results = cursor.fetchall()
    number_of_usernames_from_one_ip = len(results)

    if number_of_usernames_from_one_ip >= 3:
        cursor.execute(
            """INSERT into alerts 
            (alert_id, timestamp, alert_type, severity, source_ip, description)
            VALUES(%s,%s,%s,%s,%s,%s)""",
            (
                "2",
                datetime.now(),
                "PASSWORD SPRAYING",
                "MEDIUM",
                currentEvent.source_ip,
                "Too many accounts attempted"

            )  
        )
        conn.commit()
        return True
    else:
        return


def detectBruteForce(currentEvent: Event):
    brute_force_datetime_threshold = currentEvent.timestamp - timedelta(minutes = 5)
    cursor.execute (
        "SELECT username FROM events WHERE username = %s AND timestamp >= %s ", 
        (currentEvent.username, brute_force_datetime_threshold,)
    )
    results = cursor.fetchall()
    count = len(results)

    if count >=5:
        cursor.execute(
            """INSERT into alerts 
            (alert_id, timestamp, alert_type, severity, source_ip, description)
            VALUES(%s,%s,%s,%s,%s,%s)""",
            (
                "1",
                datetime.now(),
                "BRUTE FORCE",
                "MEDIUM",
                currentEvent.source_ip,
                "Too Many Login Attempts"
            )

        )
        conn.commit()
        return True
    else:
        return
        
    
#####end attack detection functions######


if __name__ == "__main__":
    main()




    

