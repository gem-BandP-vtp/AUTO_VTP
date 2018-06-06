try{

print("======================================================================================\n");

var crypto = new Crypto();
load("/Payment Profile Scripts/07 - Visa Contactless/qVSDC/PARAMETERS.js");

var card = new Card(_scsh3.reader);
var atr = card.reset(Card.RESET_COLD);

var atrbin = atr.toByteString();
print("ATR ... " + atrbin + "\n");


load("/Payment Profile Scripts/07 - Visa Contactless/qVSDC/emv_VISA_contactless.js");
load("/Payment Profile Scripts/07 - Visa Contactless/qVSDC/dataAuthentication_VISA_contactless.js");
load("/Payment Profile Scripts/07 - Visa Contactless/qVSDC/emvView.js");
load("/Payment Profile Scripts/07 - Visa Contactless/qVSDC/tagdes.js");


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
AIPDDA=0;
AIPCDA=0;

if(DDA_VALIDATION == 1 || CDA_VALIDATION == 1){
var AIPDDA = returnAIP[0];
var AIPCDA = returnAIP[1];
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
catch(e){
print("ERROR");
}