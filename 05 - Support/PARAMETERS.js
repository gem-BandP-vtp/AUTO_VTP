function PARAMETERS(){
}

//AID or part of AID
//A0000000041010 = MASTERCARD, A0000000043060 = MAESTRO, A0000000031010 = VISA, etc

AID1 = "A00000002501";
AID2 = "A0000000031010";
AID3 = "A0000000041010";
AID4= "A0000000043060";

/* ***************************************************************************************************/
DDA_VALIDATION = "1";
CDA_VALIDATION = "0";

/* ***************************************************************************************************/

PARAMETERS.PIN = "1234";

/* ***************************************************************************************************

/* ***************************************************************************************************
Definition of the TDES keys
KEY_AC = value of key used for TC/ARQC/ARPC/AAC generation
KEY_SMI = value of key used for Secure messaging for Integrity
KEY_SMC = value of key used for Secure messaging for Confidentialit*/


//Mastercard Credito, Visa Credito, Visa Debito
PARAMETERS.KEY_AC = "DF03333333330101DF03333333330202";
PARAMETERS.KEY_SMC = "DF03222222220101DF03222222220202";
PARAMETERS.KEY_SMI = "DF00444444440101DF00444444440202";




/*
//Mastercard Debito
PARAMETERS.KEY_AC = "A2C2DFBA237F458CF4BAC820A410D5B3";
PARAMETERS.KEY_SMC = "4EC06CAC9CA9A9BB74E4AA884E74F32D";
PARAMETERS.KEY_SMI = "0F7B816F5FC693788B95E8E782CA817E";
*/



/*
//Mastercard Debito Colombia
PARAMETERS.KEY_AC = "02296EB32362A78FDC64375BA28C2007";
PARAMETERS.KEY_SMC = "AB497307A80E9D94D5EFCEF416ABC8EF";
PARAMETERS.KEY_SMI = "07E6FB890E1038735270D515C262BF58";
*/


/*
//Broxel Mastercard Debito
PARAMETERS.KEY_AC = "01112233445566770111223344556677";
PARAMETERS.KEY_SMC = "03FF00112233445503FF001122334455";
PARAMETERS.KEY_SMI = "028899AABBCCDDEE028899AABBCCDDEE";
*/


/* ***************************************************************************************************
Certification Authority
CA_RIDx = RID
CA_IDXx = CA index (Decimal)
CA_FILEx = File in 'schemepublickeys' folder with CA Public key modulus.  */

CA_RID1 = "A000000025"; CA_IDX1 = 103; CA_FILE1 = "/Payment Profile Scripts/05 - Support/schemepublickeys/kp_AMEX_1408_103.xml";
CA_RID2 = "A000000004"; CA_IDX2 = 241; CA_FILE2 = "/Payment Profile Scripts/05 - Support/schemepublickeys/kp_MC_1408_241.xml";
CA_RID3 = "A000000003"; CA_IDX3 = 148; CA_FILE3 = "/Payment Profile Scripts/05 - Support/schemepublickeys/kp_visa_1984_94.xml";
CA_RID4 = "A000000004"; CA_IDX4 = 5; CA_FILE4 = "/Payment Profile Scripts/05 - Support/schemepublickeys/kp_MC_1408_05.xml";

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
TERM_TRANS_QUALIFIER = "27000000"					//9F66 Terminal Transaction Qualifier

AUTH_RESP_CODE = "3030"								//Authorization Response Code
AUTH_RESP_CRYPTO = "0010"							//Internal Tag - Authorization Response Cryptogram




/* ***************************************************************************************************
PUT DATA
Data to be administrated by the Put Data script
Command stands for "0xP1 0xP2"
Value stands for the data which will be put in the tag specified in the command field
[TAG(command),VALUE]
*/
PARAMETERS.PUTDATA_TAGG = "9F59"
PARAMETERS.PUTDATA_VALUE = "10"
/*Example:
//Script command upgrade value of CRM Currency Code - 2 bytes
COMMAND = "00C9"
VALUE = "0985"
*/
/* ***************************************************************************************************
UPDATE RECORD

TAG will have two hex numbers:
"0xP1" "0xP2"
"0xP1": will contain the record number you want to change
"0xP2":
b8	b7	b6	b5	b4	b3	b2	b1	Meaning:
x	x	x	x	x	 	 	 	SFI (1 to 30 decimal)
 	 	 	 	 	1	0	0	P1 is a record

VALUE will contain all of the data to be put int the record and SFI instructed earlier.
WITHOUT SPACES!!!!!!!!!!!!!!!!! VALUE MUST NOT CONTAIN SPACES
*/

PARAMETERS.UPREC_TAG="021C"
PARAMETERS.UPREC_VALUE="703F9F080200025F201A53414E54414E4445522F4D41455354524F2020202020202020209F49039F37045710589710500111111110D24122061528355F30020206"


