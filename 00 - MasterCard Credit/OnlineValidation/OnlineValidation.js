try{
print("======================================================================================\n");

var crypto = new Crypto();
load("/Payment Profile Scripts/05 - Support/PARAMETERS.js");

var card = new Card(_scsh3.reader);
var atr = card.reset(Card.RESET_COLD);

var atrbin = atr.toByteString();
print("ATR ... " + atrbin + "\n");

/*Options*/
 var DDAValidation=0;
 var CDAValidation=0;
 var OnlineValidation=1;
 var ValidatePin=0;
 var ApplicationBlock=0;
 var ApplicationUnblock=0;
 var PINChange=0;
 var PINUnblock=0;

load("/Payment Profile Scripts/05 - Support/emv.js");
load("/Payment Profile Scripts/05 - Support/emvView.js");


var p = new PARAMETERS();
var e = new EMV(card, crypto);
var v = new EMVView(e);


print("======================================================================================\n");

print("SELECT PSE/PPSE\n");

e.selectPSE(false);

print("\n======================================================================================\n");

print("RUN AN EMV TRANSACTION\n");

var aid = e.getAID();

print("======================================================================================");
print("SELECT APPLICATION");
print("======================================================================================");

if (aid != null) {
	
	print("SELECT THE APPLICATION with AID " + aid + "\n");
	e.selectADF(aid);
} else {
	e.tryAID();
}

print("======================================================================================");
print("GET PROCESSING OPTION");
print("======================================================================================");
e.initApplProc();


var aip = this.e.cardDE[EMV.AIP];

var returnAIP = v.decodeAIP(aip);
var AIPDDA = returnAIP[0];
var AIPCDA = returnAIP[1];



print("======================================================================================");
print("READ DATA");
print("======================================================================================");
e.readApplData();

var iccDynamicNumber = card.sendApdu(0x00, 0x84, 0x00, 0x00, 0x00);

e.generateAC();

}
catch(error){
if(error == "OK:"){
card.close();
throw ok + " Successful Cryptogram Validation"
}
card.close();
throw error + " No Successful Cryptogram Validation"
}