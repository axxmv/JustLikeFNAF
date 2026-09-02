#will work as an API to pass json log data into parser and detection engine from the javascript file.


from fastapi import FastAPI
app = FastAPI()


from Backend.Parser import parse_line
from Backend.DetectionEngine import EventDetection

@app.get("/")
def home():
    return {"message": "Security Log Monitor API is running"}


#make a post endpoint to load the data we will need from javascript.
@app.post("/analyze")
def analyze(instance):
    currentEvent = parse_line(instance)#put it into a nice format

    current_result = EventDetection(currentEvent)#pass to detection engine and get results

    return 
    {
        "Brute Force": current_result.bruteForce,
        "Password Spraying": current_result.passwordSpraying,
        "Port Scanning": current_result.portScanning,
        "Suspicious Login Activity": current_result.suspiciousLogin
    }
