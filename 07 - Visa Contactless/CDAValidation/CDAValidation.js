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
 var CDAValidation=1;
 var OnlineValidation=0;
 var ValidatePin=0;
 var ApplicationBlock=0;
 var ApplicationUnblock=0;
 var PINChange=0;
 var PINUnblock=0;

load("/Payment Profile Scripts/05 - Support/emv_VISA_contactless.js");
load("/Payment Profile Scripts/05 - Support/dataAuthentication_VISA_contactless.js");
load("/Payment Profile Scripts/05 - Support/emvView.js");
load("/Payment Profile Scripts/05 - Support/tagdes.js");


var p = new PARAMETERS();
var e = new EMV(card, crypto);
var d = new DataAuthentication(e);
var v = new EMVView(e);
var t = new tagdes();


d.addSchemePublicKey(new ByteString(CA_RID1, HEX), CA_IDX1, new Key(CA_FILE1));
d.addSchemePublicKey(new ByteString(CA_RID2, HEX), CA_IDX2, new Key(CA_FILE2));
d.addSchemePublicKey(new ByteString(CA_RID3, HEX), CA_IDX3, new Key(CA_FILE3));
d.addSchemePublicKey(new ByteString(CA_RID4, HEX), CA_IDX4, new Key(CA_FILE4));


print("======================================================================================\n");


print("RUN AN EMV TRANSACTION\n");


print("\n======================================================================================");




print("SELECT PSE/PPSE\n");

e.selectPSE(true);

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



if(AIPCDA != 1){
	throw na 
}

print("======================================================================================");
print("READ DATA");
print("======================================================================================");
e.readApplData();

var iccDynamicNumber = card.sendApdu(0x00, 0x84, 0x00, 0x00, 0x00);

if(AIPDDA == 1 || AIPCDA == 1){

var issuerPublicKeyModulus = d.retrieveIssuerPublicKey();



var returnFromFunction = d.retrieveICCPublicKey(issuerPublicKeyModulus);
var  iccPublicKeyModulus = returnFromFunction[0];
var  l = returnFromFunction[1];

d.dynamicDataAuthentication(iccPublicKeyModulus,l);	



}


e.generateAC();

card.close();
}
catch(error){
if(error == "OK:"){
card.close();
throw ok + " CDA Validation Successful"
}
if(error == "ERROR:"){ 
card.close();
throw error + " CDA Validation NO Successful"
}
if(error == "NA:"){
card.close();
throw na + " CDA not supported"
}
}