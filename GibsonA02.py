#GibsonA02.py
"""
Class: CSEC 1437

Menu Driven toolkit


"""
global VulnsObject
global PortScanObject
global LogFileScanObject
global SystemInfoObject
global NetInterfaceObject
global ImageMetaDataObject
global SoundMetaDataObject
global GetWebXMLObject
GetWebXMLObject = None
SoundMetaDataObject = None
ImageMetaDataObject = None
NetInterfaceObject = None
LogFileScanObject = None
VulnsObject = None
PortScanObject = None
SystemInfoObject = None

import requests
import socket
import psutil
import netifaces
import mutagen
import json
from exif import Image
from mutagen.mp3 import EasyMP3 
from bs4 import BeautifulSoup

class MenuClass():
    def __init__(self, Mitems):
        self.Menuitems = Mitems[:]
    pass

    def GetMenuChoice(self):
        """
        Returns the choice of menu
        """
        MenuNum = 0
        for Anitem in self.Menuitems:
            MenuNum += 1
            print(f"{MenuNum}.{Anitem}")
        AllGood = False
        while True:
            try:
                while True:
                    Anum = int(input(f"Enter menu choice between 1 and {len(self.Menuitems)}: "))
                    if Anum >= 1 and Anum <= len(self.Menuitems):
                        AllGood = True
                        break
                    else:
                        print(f"Enter number between 1 and {len(self.Menuitems)}")
                if AllGood:
                    break
            except ValueError:
                #print(f"The choice is: {self.Menuitems[Anum-1]}")
                pass
        print(f"The choice is: {self.Menuitems[Anum-1]}\n")
        return self.Menuitems[Anum-1]

class VulnsJsonClass():
    """
    This class serves to collect and gather data from cisa.gov vulnerabilities.json file
    """
    def __init__(self, website = ""):
        """
        This method serves to automatically run whenever a VulnsJsonClass object is created
        """
        if website == "":
            Vulns = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')   #Gets the Vulns.json file 
        else:
            Vulns = requests.get(website)
        self.VulnsJson = Vulns.json() #Assigns our Vulns.json data to a variable within the class 
        print(f"CISA Vulnerabilities obtained")
    
    def GetNumberOfVulnerabilities(self):
        """
        Retrieves the total number of vulnerabilities in our vulnsjson folder
        """
        for key, value in self.VulnsJson.items():
            if key == "vulnerabilities":
                VulnsList = value
        return(len(VulnsList))
    
    def GetVendorVulnerabilities(self, Vendor):
        """
        Searches vulnerabilities for a specific vendor and returns them as a list
        """
        VendorVulnList = [] #initialize list
        for key,value in VulnsObject.VulnsJson.items():
            if key == 'vulnerabilities':
                VulnList = value

        for Anitem in VulnList:
            for key, value in Anitem.items():
                if key.lower() == 'vendorproject':
                    if Vendor.lower() == value.lower():
                        VendorVulnList.append([Anitem['vulnerabilityName'],Anitem['cveID'],Anitem['dateAdded']])
        return VendorVulnList

class GibsonPortScannerClass():

    def SetTargetIP(self):
        """
        This will set the target IP of our port scan.
        """
        AddAnotherIP = 'Y'
        TargetIPList = []
        while AddAnotherIP == 'Y':
            TargetIP = str(input(f"Please enter the IP you wish to scan: "))
            TargetIPList.append(TargetIP)
            AddAnotherIP = str(input(f"Would you like to add another IP to scan (Y/N)?: "))
        print(f"The target IPs have been set.")
        self.IPList = TargetIPList
        return TargetIPList
    
    def ReadStandardPorts(self):
        """
        This will read the standard ports from PortNums.txt
        """
        IFile = open('PortNums.txt', 'r').readlines()
        PortList = []
        for port in IFile:
            PortList.append(int(port.strip()))
        print(f"Standard ports have been added to a list!")
        self.PortList = PortList
        return PortList

    def SetTimeout(self):
        """
        This will allow the user to set a timeout for the port scanner
        """
        while True:
            try:
                UserTimeout = float(input(f"Please enter the timeout period for port scanning in seconds in the range of (1.00 - 0.05): "))
                if UserTimeout <= 1.00 and UserTimeout >= .05:
                    break
                else:
                    print(f"**ERROR** The timeout you entered was {UserTimeout} this outside the range of (1.00 - 0.05)")
            except ValueError:
                print(f"**ERRORR** The value you've entered is not accepted please try again")
                pass
        print(f"Timeout has been set.")
        self.Timeout = UserTimeout
        return UserTimeout

    def PortScan(self, IPList, Ports, Timeout):
        """
        This method will actually do the port scanning using the information our user enters
        """
        print(f"Port scanning has begun....")
        portsscanned = 0 #Counter
        OpenPortList = [] #List of open ports
        for IPs in IPList:
            for PortNumber in Ports: #Loops through every port
                portsscanned += 1 # Keeps count of how many ports we've scanned 
                if portsscanned % 100 == 0: #If we've scanned 100 ports 
                    print(f"{portsscanned} Ports have been scanned...") #Print the running count. 
                mysession = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Checks the connectioin
                mysession.settimeout(Timeout) #Sets the timeout.
                if mysession.connect_ex((IPs, PortNumber)) == 0:  #If the port is discovered to be open
                        #print(f"IPNum: {IPNumber}, Port No: {PortNumber} is open")   #Prints the results
                        OpenPort = (f'IP: {IPs} Open Port:{PortNumber}')     #Creates an object using our results
                        OpenPortList.append(OpenPort) #Appends that object to a list of open ports
                else:
                    #print(f"IPNum: {IPNumber}, Port No: {PortNumber} is closed")
                    pass

        print(f"The open ports were....")
        for aline in OpenPortList:
            print(f"{aline}")
        
        SaveToFile = input(f"Would you like to save the output to a file? (Y/N)")
        if SaveToFile == 'Y':
            GibsonPortScannerClass.SaveToFile(self,OpenPortList)
        else:
            pass

    def SaveToFile(self, OpenPorts):
        """
        This will be responsible for saving the open port date to a file
        """
        OFile = open('PortScanOutput.txt', 'w')
        OFile.write(f"There were {len(OpenPorts)} open ports found those ports are....\n")
        for aline in OpenPorts:
            OFile.write(f"{aline}\n")
        OFile.close()
        print(f"The Output File has been created.")

class GibsonFileLogScanner():
    def SetTargetFile(self):
        """
        This method will set our users target log file to scan
        """
        while True:
            UserFile = str(input(f"Please enter the name of the file you wish to search (EX: Auth.log): "))
            try:
                IFile = open(UserFile, 'r').readlines() # 2. Read the file to a list of lines. 
            except FileNotFoundError:
                print(f"**ERROR** The file you entered was not found!! Please try again.")
                pass
            else:
                print(f"File found!")
                print(f"The number of lines in the file are: {len(IFile)}")
                break
        self.UserFile = UserFile
        return UserFile



    def SetTargetWords(self):
        """
        This method will determine our users search words 
        """
        WordSearch = str(input(f"Please enter the words you'd like to search in any line seperated by a ^ (EX: Hello^World^72): "))
        WordSearchList = WordSearch.split('^')
        print(f"The number of words you're searching for is {len(WordSearchList)}")
        self.WordSearchList = WordSearchList
        return WordSearchList


    def ScanLogFile(self, UserFile, WordSearchList):
        """
        This will scan the users log file for the words provided and return the output of where all words were found or any words were found
        """
        linenumber = 0
        counter = 0
        Allwordsfound = []
        IFile = open(UserFile, 'r').readlines()
        for aline in IFile: #Loops line by line in IFile
            linenumber += 1 #Keeps track of line number
            for aword in WordSearchList: #Loops through all of the words we're searching for as entered by the user
                if aline.find(aword) != -1: #If the word is found add one to the counter
                    counter += 1
                    if counter == len(WordSearchList): #If all of the words our user searched for are found 
                        Allwordsfound.append(f"{linenumber}:{aline}") #Add the lines to a list.
                        counter = 0 #Resets counter so we can search again.
                else:
                    counter = 0
                    break
            pass
        
        print(f"The number of lines with ALL words are: {len(Allwordsfound)} Those lines are...\n")
        for index in Allwordsfound:
            print(f"{index}")
        
        linenumber = 0
        Anywordsfound = []
        for aline in IFile: #Loops line by line in IFile
            linenumber += 1 #Keeps track of line number
            for aword in WordSearchList: #Loops through all of the words we're searching for as entered by the user
                if aline.find(aword) != -1: #If the word is found append to list and break
                    Anywordsfound.append(f"{linenumber}:{aline}")
                    break

        print(f"The number of lines with ANY words are: {len(Anywordsfound)} Those lines are...\n")
        for index in Anywordsfound:
            print(f"{index}")

        SaveToFile = input(f"Would you like to save the output to a file? (Y/N)")
        if SaveToFile == 'Y':
            GibsonFileLogScanner.SaveToFile(self,Anywordsfound,Allwordsfound)
        else:
            pass



    def SaveToFile(self,AnyWords,AllWords):
        """
        This will be responsible for saving our file log scanning results to a file
        """
        OFile = open("LogFileScanningOutput.txt", 'w')
        OFile.write((f"The number of lines with ALL words are: {len(AllWords)} Those lines are...\n"))
        for aline in AllWords:
            OFile.write(f"{aline}\n")
        OFile.write(f"The number of lines with ANY words are: {len(AnyWords)} Those lines are...\n")
        for aline in AnyWords:
            OFile.write(f"{aline}\n")

        OFile.close()
        print(f"The Output File has been created.")       
        
class DisplaySystemInfo():
    """
    This class will be used for gathering our system information data
    """

    def ViewPIDs(self):
        """
        Print the process IDs associated with the processes running on the computer
        """
        AllPids = psutil.pids()
        print(f"The number of running processes are: {len(AllPids)}")
        #To look at the details of each process associated with the PID, we use the process method
        # for APid in AllPids:
        #     Aprocess = psutil.Process(APid) #Creating a process object for each pid
        
        for AProc in psutil.process_iter(['pid','name','username','status']):
            print(f"{AProc.info['pid']:<10d}{AProc.info['name']:<40s}{AProc.info['username']}{AProc.info['status']}")

    def ViewDiskData(self):
        """
        Method to look at the disk information

        """
        print(f"Disk partitions are: {(psutil.disk_partitions())}\n")
        print(f"Disk usage: {psutil.disk_usage('/')}\n")
        print(f"Disk counters: {psutil.disk_io_counters()}\n")

    def ViewUsers(self):
        """
        A method to view the list of users 
        """
        from datetime import datetime
        
        for Auser in psutil.users():
            print(f"User: {Auser.name} StartTime UTC: {datetime.utcfromtimestamp(Auser.started)}")
            print(f"User: {Auser.name} StartTime Local: {datetime.fromtimestamp(Auser.started)}")

    def ViewNetConnections(self):
        """
        A method to view network connections
        """
        print(f"There are {len(psutil.net_if_addrs().keys())} Network Connections\n")
        for k,v in psutil.net_if_addrs().items():
            print(f"{k}\n")
            for Aval in v:
                print(f"family: {Aval.family}\naddress: {Aval.address}\nnetmask: {Aval.netmask}\nbroadcast: {Aval.broadcast}\nPTP: {Aval.ptp}\n")
            print(f"")

    def ViewCPUStats(self):
        cpustats = psutil.cpu_stats()
        print(f"The number of logical CPUs in the system are: {psutil.cpu_count()}\n")
        print(f"The number of ctx_switches are: {(cpustats.ctx_switches)}\n")
        print(f"The number of interrupts are: {(cpustats.interrupts)}\n")
        print(f"The number of syscalls are: {(cpustats.syscalls)}\n")
        print(f"The number of soft interrupts are: {(cpustats.soft_interrupts)}\n")

class NetInterfacesClass():
    """
    This class will gather network data such as IP, Netmask, Broadcast
    """
    def __init__(self):
        """
        Get the network interface details using netifaces
        """
        MyInterFaces = netifaces.interfaces()
        NetData = []
        for AnInterface in MyInterFaces:
            ipaddresses = netifaces.ifaddresses(AnInterface)
            #print(f"{MyInterFaces}")
            if netifaces.AF_INET in ipaddresses: #only for ipv4 addresses
                ipaddresses_desc = ipaddresses[netifaces.AF_INET][0] #getting the description of the ipv4 addresses
                #print(f"Contents: {ipaddresses_desc}")
                NetData.append(ipaddresses_desc)
        self.NetInterfacesData = NetData
        self.ipaddresses = ipaddresses

    
    def ViewIPAddress(self):
        """
        This method will display our IP Addresses
        """

        print(f"There are {len(self.NetInterfacesData) + len(self.ipaddresses)} IP addresses, The IP addresses are: \n")

        for ip in self.ipaddresses:
            print(f"{ip}\n")

        for IPAdress in self.NetInterfacesData:
            print(f"{IPAdress['addr']}\n")


    def ViewNetmask(self):
        """
        This will print our netmasks
        """
        print(f"There are {len(self.NetInterfacesData)} Netmasks, The netmasks are: \n")
        for Netmask in self.NetInterfacesData:
            print(f"{Netmask['netmask']}\n")

    def ViewBroadcast(self):
        """
        This method will print out broadcasts 
        """
        print(f"There are {len(self.NetInterfacesData)} Broadcast Addresses, The Broadcast Addresses are: \n")
        for Netmask in self.NetInterfacesData:
            print(f"{Netmask['broadcast']}\n")

class ImageMetaDataClass():
    def __init__(self):
            while True:
                FileName = str(input(f"Please enter the name of the image file you wish to use: "))
                try:
                    with open(FileName, 'rb') as Infile: #b i for binary file
                        MyImage1 = Image(Infile)
                except FileNotFoundError:
                        print(f"**Error** The file could not be found! Please try again")
                else:
                    print(f"The image was succesfully loaded!")
                    break
            self.MyImage = MyImage1
            self.FileName = FileName

    
    def EditMetaData(self, Module):
        while True:
            EditMetaData = str(input(f"Would you like to edit the '{Module}' metadata (Y/N): "))
            if EditMetaData == 'Y' or EditMetaData == 'y':
                NewMetaData = str(input(f"What would you like to change the metadata to?: "))
                self.MyImage[Module] = NewMetaData
                with open(self.FileName,'wb') as Ofile:
                    Ofile.write(self.MyImage.get_file())
                    print(f"Succesfully Edited the image metadata")
                break
            elif EditMetaData == 'N' or EditMetaData == 'n':
                break
            else:
                print(f"**ERROR** You entered a value not recognized, Try again. ")

    
    def ViewCameraInfo(self):
        print(f"Camera Make: {self.MyImage.make}")
        print(f"Camera Model: {self.MyImage.model}")
        print(f"Camera Flashpix: {self.MyImage.get('flashpix_version', 'Not known')}")
        ImageMetaDataObject.EditMetaData('make')
        ImageMetaDataObject.EditMetaData('model')
        ImageMetaDataObject.EditMetaData('flashpix_version')

    
    def ViewGPSInfo(self):
        print(f"GPS {self.MyImage.gps_longitude}\nref: {self.MyImage.gps_longitude_ref}\nAltitude: {self.MyImage.gps_altitude}")
        ImageMetaDataObject.EditMetaData('gps_longitude')
        ImageMetaDataObject.EditMetaData('gps_longitude_ref')
        ImageMetaDataObject.EditMetaData('gps_altitude')

    def ViewImageDemensions(self):
        print(f"Image Width: {self.MyImage.image_width}px")
        print(f"Image Height: {self.MyImage.image_height}px")
        ImageMetaDataObject.EditMetaData('image_width')
        ImageMetaDataObject.EditMetaData('image_height')

class SoundMetaDataClass():
    """
    This is our class for getting sound file meta data
    """
    def __init__(self):
        """
        Gets users sound file 
        """
        MySoundFile = str(input(f"Please enter the name of the sound file to use: "))
        MySoundMP3 = EasyMP3(MySoundFile)
        self.MySound = MySoundMP3

    def GetFileLength(self):
        """
        Gets length of sound file
        """
        return self.MySound.info.length

    def GetFileBitrate(self):
        """
        Gets bitrate of sound file
        """
        return self.MySound.info.bitrate

    def GetSongVersion(self):
        """
        Gets version of sound file
        """
        return self.MySound.info.version

class GetWebXMLClass():
    def ScanNewsFeed(self):
        """
        This will scan a preset list of websites 
        """
        SourceURLDnary = {'FoxNews':'http://feeds.foxnews.com/foxnews/tech',
                            'CNN':'http://rss.cnn.com/rss/cnn_tech.rss',
                            'BBC':'http://feeds.bbci.co.uk/news/technology/rss.xml',
                            'ABC':'http://feeds.abcnews.com/abcnews/technologyheadlines',
                            'CBS':'https://www.cbsnews.com/latest/rss/technology'}
        SourceTitlesDnary = {} #Initilize our Sources & titles Dictonary
        for Source,URL in SourceURLDnary.items():
            NewsDataList = [] #A list to collect news titles
            URLRAW = requests.get(URL).content #Uses the request library to go to news website
            SoupXML = BeautifulSoup(URLRAW, 'xml') #Uses beautiful Soup library to get XML data
            #print(f"{Source}")
            for index,item in enumerate(SoupXML.find_all('item')): # Loops through website XML data
                Atitle = item.find('title').text #Newstitle is asigned to Atitle
                if len(Atitle) != 0: #checks for blank titles
                    NewsDataList.append(Atitle.strip()) #adds titles to list 
            SourceTitlesDnary[Source] = NewsDataList #adds sources and titles to dnary
        
        self.SourcesTitlesDnary = SourceTitlesDnary
        return self.SourcesTitlesDnary
    
    def ScanFromFile(self):
        """
        This will scan XML feeds from a user file
        """
        while True:
            UserFile = str(input(f"Please enter the name of the file you wish to scan: "))
            try:
                IFile = open(UserFile, 'r').read().strip().split()
            except FileNotFoundError:
                print(f"The file you entered was not found, please try again.: ")
                pass
            else:
                break

        SourceURLDnary = {} #This stores the source & URL to a dicotnary
        for Awebsite in IFile: 
            Value = Awebsite #Stores URL to a value
            Key = Awebsite.split('.')[1] #splits on commas and grabs website name
            SourceURLDnary[Key] = Value #Adds to dictonary

        SourceTitlesDnary = {} #Initilize our Sources & titles Dictonary
        for Source,URL in SourceURLDnary.items():
            NewsDataList = [] #A list to collect news titles
            URLRAW = requests.get(URL).content #Uses the request library to go to news website
            SoupXML = BeautifulSoup(URLRAW, 'xml') #Uses beautiful Soup library to get XML data
            #print(f"{Source}")
            for index,item in enumerate(SoupXML.find_all('item')): # Loops through website XML data
                Atitle = item.find('title').text #Newstitle is asigned to Atitle
                if len(Atitle) != 0: #checks for blank titles
                    NewsDataList.append(Atitle.strip()) #adds titles to list 
            SourceTitlesDnary[Source] = NewsDataList #adds sources and titles to dnary
        
        self.SourcesTitlesDnary = SourceTitlesDnary
        return self.SourcesTitlesDnary


    def SaveToJSON(self):
        UserOFile = str(input(f"Please enter the name of the output file (.json): "))
        OFile = open(UserOFile, 'w') #Opens our output file as a .json
        json.dump(self.SourcesTitlesDnary, OFile) #Dumps all of our data to .json file
        OFile.close()
        print(f"The news titles have been saved to a JSON File")
        self.UserOFile = UserOFile
        return self.UserOFile

    def ViewNewsTitles(self):
        """
        This is responsible for displaying the datafrom the JSON file
        """
        counter = 0 #Initilize Counter
        IFile = open(self.UserOFile, 'r') #Opens .json output file 
        NewsData = json.load(IFile) #Loads data from output file to NewsData as a dictonary
        for Source,NewsTitle in NewsData.items(): #Loops through sources and titles in news data
            print(f"{Source:>}") #Prints the source
            for Titles in NewsTitle: # Loops through titles in a source
                counter += 1 #Keeps track of how many titles printed
                print(f"{counter}. {Titles}") #Prints titles and number
                if counter == 10: #Once 10 titles are printed
                    break #Break from the loop
            counter = 0 # reset counter 
        IFile.close()

def ProcessImageMetaDataMenu(MyChoice):
    global ImageMetaDataObject
    if MyChoice == 'View Camera Info':
        ImageMetaDataObject = ImageMetaDataClass()
        ImageMetaDataObject.ViewCameraInfo()
    elif MyChoice == 'View GPS Info':
        ImageMetaDataObject = ImageMetaDataClass()
        ImageMetaDataObject.ViewGPSInfo()
    elif MyChoice == 'View Image Demensions':
        ImageMetaDataObject = ImageMetaDataClass()
        ImageMetaDataObject.ViewImageDemensions()
    elif MyChoice == 'Return to previous menu':
        DisplayForensicsMenu()
    else:
        print(f"You have reached the point of no return in the image meta data menu")

def ProcessSoundMetaDataMenu(MyChoice):
    global SoundMetaDataObject
    if MyChoice == 'View Length':
        SoundMetaDataObject = SoundMetaDataClass()
        print(f"The length of the file is: {SoundMetaDataObject.GetFileLength()}")
    elif MyChoice == 'View Bitrate':
        SoundMetaDataObject = SoundMetaDataClass()
        print(f"The bitrate of the file is: {SoundMetaDataObject.GetFileBitrate()}")
    elif MyChoice == 'View Version':
        SoundMetaDataObject = SoundMetaDataClass()
        print(f"The version of the file is: {SoundMetaDataObject.GetSongVersion()}")
    elif MyChoice == 'Return to previous menu':
        DisplayForensicsMenu()
    else: 
        print(f"You have reached the point of no return in Forensics Menu")

def ProcessForensicsMenu(MyChoice):
    if MyChoice == "LogFileScanning":
        DisplayLogFileScanning()
    elif MyChoice == 'View System Information':
        DisplaySystemMenu()
    elif MyChoice == 'View Network Interfaces':
        DisplayNetInterfacesMenu()
    elif MyChoice == 'Edit Image Metadata':
        ImageMetaDataMenu()
    elif MyChoice == 'Edit Sound Metadata':
        SoundMetaDataMenu()
    elif MyChoice == "Go To Main Menu":
        DisplayMainMenu()
    else: 
        print(f"You have reached the point of no return in Forensics Menu")

def ProcessNetInterfaces(MyChoice):
    global NetInterfaceObject
    NetInterfaceObject = NetInterfacesClass()
    if MyChoice == "Get IP Address":
        NetInterfaceObject.ViewIPAddress()
    elif MyChoice == 'Get Netmask':
        NetInterfaceObject.ViewNetmask()
    elif MyChoice == 'Get Broadcast':
        NetInterfaceObject.ViewBroadcast()
    elif MyChoice == "Return to previous menu":
        DisplayForensicsMenu()
    else:
        print(f"You have reached the point of no return in the Net Interfaces Menu")

def ProcessSystemMenu(MyChoice):
    global SystemInfoObject
    SystemInfoObject = DisplaySystemInfo()
    if MyChoice == 'View Process IDs':
        SystemInfoObject.ViewPIDs()
    elif MyChoice == 'View Disk Partitions':
        SystemInfoObject.ViewDiskData()
    elif MyChoice == 'View Users':
        SystemInfoObject.ViewUsers()
    elif MyChoice == 'View Network Connections':
        SystemInfoObject.ViewNetConnections()
    elif MyChoice == 'View CPU Stats':
        SystemInfoObject.ViewCPUStats()
    elif MyChoice == 'Return to previous menu':
        DisplayForensicsMenu()
    else:
        print(f"You have reached the point of no return in the System Info Menu")

def ProcessLogFileScanning(MyChoice):
    global LogFileScanObject
    LogFileScanObject = GibsonFileLogScanner()
    if MyChoice == 'Set Search File':
        LogFileScanObject.SetTargetFile()
    elif MyChoice == 'Set Target Words':
        LogFileScanObject.SetTargetWords()
    elif MyChoice == 'Scan Log File':
        LogFileScanObject.ScanLogFile(LogFileScanObject.UserFile, LogFileScanObject.WordSearchList)
    elif MyChoice == 'Return to previous menu':
        DisplayForensicsMenu()

def ProcessNetToolsMenu(MyChoice):
    global PortScanObject
    if MyChoice == 'Port Scanning':
        PortScanObject = GibsonPortScannerClass()
        DisplayPortScanning()
    elif MyChoice == 'Go To Main Menu':
        DisplayMainMenu()
    else:
        print(f"You have reached the point of no return in NetTools Menu")
        DisplayMainMenu()

def ProcessWebDataMenu(MyChoice):
    if MyChoice == 'Get Web XML Pages':
        DisplayWebXMLMenu()
    elif MyChoice == "Check Data Vulnerabilities":
        DisplayVulnsListMenu()
    elif MyChoice == "Go back to main menu":
        DisplayMainMenu()
    else: 
        print(f"You have reached the point of no return in Web Data Menu")
        DisplayMainMenu()

def ProcessWebXMLMenu(MyChoice):
    global GetWebXMLObject
    if MyChoice == 'Scan from preset XML websites':
        GetWebXMLObject = GetWebXMLClass()
        GetWebXMLObject.ScanNewsFeed()
    elif MyChoice == 'Scan XML websites from file':
        GetWebXMLObject = GetWebXMLClass()
        GetWebXMLObject.ScanFromFile()
    elif MyChoice == 'Save news titles to JSON':
        GetWebXMLObject.SaveToJSON()
    elif MyChoice == 'View News Titles':
        GetWebXMLObject.ViewNewsTitles()
    elif MyChoice == 'Return to Previous menu':
        DisplayWebDataAcessMenu()
    else:
        print(f"You have reached the point of no return in the Web XML menu")

def ProcessPortScanMenu(MyChoice):
    if MyChoice == 'Set Target IP':
        IPList = PortScanObject.SetTargetIP()
    elif MyChoice == 'Read Standard Ports From File':
        Ports = PortScanObject.ReadStandardPorts()
    elif MyChoice == 'Set Timeout':
        Timeout = PortScanObject.SetTimeout()
    elif MyChoice == 'Port Scan':
        PortScanObject.PortScan(PortScanObject.IPList, PortScanObject.PortList, PortScanObject.Timeout)
    elif MyChoice == 'Return to Previous menu':
        DisplayNetToolsMenu()
    else:
        print(f"You have reached the point of no return in portscanning menu")
        DisplayMainMenu()

def ProcessVulnsListMenu(MyChoice):
    global VulnsObject
    if MyChoice == "Get Vulnerabilities":
        VulnsObject = VulnsJsonClass()
    elif MyChoice == "Display Number of Vulnerabilities":
        print(f"The number of Vulnerabilities is: {VulnsObject.GetNumberOfVulnerabilities()}")
    elif MyChoice == "Get Vendor Vulnerabilities":
        Vendor = str(input(f"Please enter the name of the vendor you'd like to search for: "))
        VendorVulnList = VulnsObject.GetVendorVulnerabilities(Vendor)
        print(f"The vendor: {Vendor} has {len(VendorVulnList)} vulnerabilities...")
        print(f"{'Vuln Name':<115s}{'cveID':<20s}{'Date Added':<35s}")
        for anitem in VendorVulnList:
            print(f"{anitem[0]:<115s}{anitem[1]:<20s}{anitem[2]:<35s}")
    elif MyChoice == "Go back to main menu":
        DisplayMainMenu()
    else: 
        print(f"You have reached the point of no return in Vulns list Menu")
        DisplayMainMenu()

def ProcessMainMenu(UserChoice):
    if UserChoice == "Forensics Menu":
        DisplayForensicsMenu()
    elif UserChoice == "Network Tools":
        DisplayNetToolsMenu()
    elif UserChoice == "Get Web Data Menu":
        DisplayWebDataAcessMenu()
    elif UserChoice == "Quit The Program":
        exit()

def DisplayNetInterfacesMenu():
    while True:
        NetInterfacesMenu = MenuClass(['Get IP Address', 'Get Netmask', 'Get Broadcast', 'Return to previous menu'])
        MyChoice = NetInterfacesMenu.GetMenuChoice()
        ProcessNetInterfaces(MyChoice)

def DisplayLogFileScanning():
    while True:
        LogFileScanMenu = MenuClass(['Set Search File', 'Set Target Words', 'Scan Log File', 'Return to previous menu'])
        MyChoice = LogFileScanMenu.GetMenuChoice()
        ProcessLogFileScanning(MyChoice)

def ImageMetaDataMenu():
    while True:
        DisplayImageMetaData = MenuClass(['View Camera Info','View GPS Info','View Image Demensions','Return to previous menu'])
        MyChoice = DisplayImageMetaData.GetMenuChoice()
        ProcessImageMetaDataMenu(MyChoice)

def SoundMetaDataMenu():
    while True:
        DisplaySoundMetaData = MenuClass(['View Length','View Bitrate','View Version', 'Return to previous menu'])
        MyChoice = DisplaySoundMetaData.GetMenuChoice()
        ProcessSoundMetaDataMenu(MyChoice)

def DisplayForensicsMenu():
    while True:
        DisplayForensicsMenu = MenuClass(['LogFileScanning','View System Information','View Network Interfaces','Edit Image Metadata','Edit Sound Metadata', 'Go To Main Menu'])
        MyChoice = DisplayForensicsMenu.GetMenuChoice()
        ProcessForensicsMenu(MyChoice)

def DisplaySystemMenu():
    while True:
        DisplaySystemInfo = MenuClass(['View Process IDs','View Disk Partitions','View Users','View Network Connections','View CPU Stats','Return to previous menu'])
        MyChoice = DisplaySystemInfo.GetMenuChoice()
        ProcessSystemMenu(MyChoice)

def DisplayPortScanning():
    while True:
        PortScanningMenu = MenuClass(['Set Target IP', 'Read Standard Ports From File', 'Set Timeout', 'Port Scan', 'Return to previous menu'])
        MyChoice = PortScanningMenu.GetMenuChoice()
        ProcessPortScanMenu(MyChoice)

def DisplayNetToolsMenu():
    while True:
        NetToolsMenu = MenuClass(['Port Scanning', 'Go To Main Menu'])
        MyChoice = NetToolsMenu.GetMenuChoice()
        ProcessNetToolsMenu(MyChoice)

def DisplayWebDataAcessMenu():
    while True:
        VulnsListMenu = MenuClass(['Get Web XML Pages', 'Check Data Vulnerabilities', 'Go back to main menu'])
        MyChoice = VulnsListMenu.GetMenuChoice()
        ProcessWebDataMenu(MyChoice)

def DisplayWebXMLMenu():
    while True:
        WebXMLListMenu = MenuClass(['Scan from preset XML websites','Scan XML websites from file', 'Save news titles to JSON', 'View News Titles','Return to Previous menu'])
        MyChoice = WebXMLListMenu.GetMenuChoice()
        ProcessWebXMLMenu(MyChoice)

def DisplayVulnsListMenu():
    while True:
        VulnsListMenu = MenuClass(['Get Vulnerabilities', 'Display Number of Vulnerabilities', 'Get Vendor Vulnerabilities', 'Go back to main menu'])
        MyChoice = VulnsListMenu.GetMenuChoice()
        ProcessVulnsListMenu(MyChoice)

def DisplayMainMenu():
    while True:
        ToolKitMenu = MenuClass(["Forensics Menu","Network Tools","Get Web Data Menu","Quit The Program"])
        MyChoice = ToolKitMenu.GetMenuChoice()
        #print(f"Main menu choice {MyChoice}")
        ProcessMainMenu(MyChoice)

def main():
    DisplayMainMenu()
    print(f"class menu program end")

if __name__ == "__main__":
    main()