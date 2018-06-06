function PARAMETERS(){
}

//AID or part of AID
//A0000000041010 = MASTERCARD, A0000000043060 = MAESTRO, A0000000031010 = VISA, etc

AID1 = "A00000002501";
AID2 = "A0000000031010";
AID3 = "A0000000041010";
AID4 = "A0000000043060";

/* ***************************************************************************************************/	
DDA_VALIDATION = "1";
CDA_VALIDATION = "0";

/* ***************************************************************************************************

/* ***************************************************************************************************
Definition of the TDES keys
KEY_AC = value of key used for TC/ARQC/ARPC/AAC generation
KEY_SMI = value of key used for Secure messaging for Integrity
KEY_SMC = value of key used for Secure messaging for Confidentialit*/

PARAMETERS.KEY_AC = "DF03333333330101DF03333333330202";
PARAMETERS.KEY_SMC = "DF00444444440101DF00444444440202";
PARAMETERS.KEY_SMI = "DF03222222220101DF03222222220202";

/* ***************************************************************************************************
Certification Authority
CA_RIDx = RID 
CA_IDXx = CA index (Decimal)
CA_FILEx = File in 'schemepublickeys' folder with CA Public key modulus.  */

CA_RID1 = "A000000025"; CA_IDX1 = 103; CA_FILE1 = "/Payment Profile's Scripts/05 - Support/schemepublickeys/kp_AMEX_1408_103.xml";
CA_RID2 = "A000000004"; CA_IDX2 = 241; CA_FILE2 = "/Payment Profile's Scripts/05 - Support/schemepublickeys/kp_MC_1408_241.xml";
CA_RID3 = "A000000003"; CA_IDX3 = 146; CA_FILE3 = "/Payment Profile's Scripts/05 - Support/schemepublickeys/kp_visa_1408_92.xml";
CA_RID4 = "A000000004"; CA_IDX4 = 5; CA_FILE4 = "/Payment Profile's Scripts/05 - Support/schemepublickeys/kp_MC_1408_05.xml";

/* ***************************************************************************************************
Data Elements normally provided by the terminal
*/
TRANS_AMOUNT = "000000006000"						//9F02 (12 numeric digits)
AMOUNT_OTHER = "000000000000"						//9F03 (12 numeric digits)
TERM_COUNTRY_CODE = "0152"							//9F1A (04 numeric digits)
TRANS_CURRENCY_CODE = "0152"						//5F2A (04 numeric digits)
TRANS_DATE = "170721"								//9A 'YYMMDD' (04 numeric digits)
TRANS_TYPE = "00"									//9C (02 numeric digits)
UN_NUMBER = crypto.generateRandom(4)				//9F37 'Randomly generated'(8 Hex digits)
TERMINAL_TYPE = "22"								//9F35 (02 numeric digits) 21=Online only  22=Offline+Online  23=Offline only
TERM_CAPABILITY = "2028C0"							//9F33 Indicates the card data input, CVM, and security capabilities of the terminal
ADD_TERM_CAPAB = "0200000000"						//9F40 Indicates the data input and output capabilities of the terminal
CVM_RESULT = "420302";								//9F34 CVM Result (method + condition + result['00' = Unknown - '01' = Failed - '02' = Successful)
DAC = "0000";										//DAC Data Auth Code
TERM_TRANS_QUALIFIER = "35000000"					//9F66 Terminal Transaction Qualifier

AUTH_RESP_CODE = "3030"								//Authorization Response Code
AUTH_RESP_CRYPTO = "0010"							//Internal Tag - Authorization Response Cryptogram
