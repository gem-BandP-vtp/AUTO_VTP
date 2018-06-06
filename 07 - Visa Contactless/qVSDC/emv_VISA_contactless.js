/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2009 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview The EMV class contains necessary functions for transaction processing
 */



/**
 * EMV class constructor
 * @class This class implements functions for the EMV tansaction process 
 * @constructor
 * @param {object} card the card object 
 * @param {object} crypto the crypto object
 */
function EMV(card, crypto) {
	
	this.card = card;
	this.crypto = crypto;
	this.cardDE = new Array();
	this.terminalDE = new Array();

	this.terminalDE[EMV.UN] = UN_NUMBER;

	this.terminalDE[0x9F33] = new ByteString(TERM_CAPABILITY, HEX);
	this.terminalDE[0x9F1A] = new ByteString(TERM_COUNTRY_CODE, HEX);
	this.terminalDE[0x9F35] = new ByteString(TERMINAL_TYPE, HEX);
	this.terminalDE[0x9F40] = new ByteString(ADD_TERM_CAPAB, HEX);
	this.terminalDE[0x9F66] = new ByteString(TERM_TRANS_QUALIFIER, HEX);
	this.terminalDE[0x9F02] = new ByteString(TRANS_AMOUNT, HEX);
	this.terminalDE[0x9F03] = new ByteString(AMOUNT_OTHER, HEX);
	this.terminalDE[0x95] = new ByteString("0000000000", HEX);
	this.terminalDE[0x5F2A] = new ByteString(TRANS_CURRENCY_CODE, HEX);
	this.terminalDE[0x9A] = new ByteString(TRANS_DATE, HEX);
	this.terminalDE[0x9C] = new ByteString(TRANS_TYPE, HEX);
	
	
	this.terminalDE[0x9F34] = new ByteString(CVM_RESULT, HEX);
	this.terminalDE[0x9F45] = new ByteString(DAC, HEX);
	this.issuerDE = new Array();
	this.issuerDE[0x8A] = new ByteString(AUTH_RESP_CODE, HEX); //Authorization Response Code
	this.issuerDE[0x1F68] = new ByteString(AUTH_RESP_CRYPTO, HEX); //Internal Tag - Authorization Response Cryptogram 
	
	this.verbose = false;
}



// Constants

EMV.PSE1 = new ByteString("1PAY.SYS.DDF01", ASCII);
EMV.PSE2 = new ByteString("2PAY.SYS.DDF01", ASCII);

EMV.INS_GET_PROCESSING_OPTIONS		= 0xA8;

EMV.AID				= 0x4F;
EMV.LABEL			= 0x50;
EMV.FCI				= 0x6F;
EMV.TEMPLATE		= 0x70;
EMV.RMTF2			= 0x77;
EMV.RMTF1			= 0x80;
EMV.AIP				= 0x82;
EMV.DFNAME			= 0x84;
EMV.PRIORITY		= 0x87;
EMV.SFI				= 0x88;
EMV.CDOL1			= 0x8C;
EMV.CDOL2			= 0x8D;
EMV.CAPKI			= 0x8F;
EMV.AFL				= 0x94;
EMV.FCI_ISSUER		= 0xA5;
EMV.UN				= 0x9F37;
EMV.PDOL			= 0x9F38;
EMV.SDATL			= 0x9F4A;
EMV.FCI_ISSUER_DISCRETIONARY_DATA = 0xBF0C;
EMV.DIRECTORY_ENTRY	= 0x61;

EMV.AIDLIST = new Array();
EMV.AIDLIST[0] = { aid : new ByteString(AID1,HEX), partial : true, name : "AMEX" };
EMV.AIDLIST[1] = { aid : new ByteString(AID2,HEX), partial : false, name : "VISA" };
EMV.AIDLIST[2] = { aid : new ByteString(AID3,HEX), partial : false, name : "MC" };
EMV.AIDLIST[3] = { aid : new ByteString(AID4,HEX), partial : false, name : "MAESTRO" };
EMV.TAGLIST = new Array();
EMV.TAGLIST[EMV.UN] = { name : "Unpredictable Number" };
EMV.TAGLIST[EMV.CAPKI] = { name : "Certification Authority Public Key Index" };
EMV.TAGLIST[EMV.SDATL] = { name : "Static Data Authentication Tag List" };
EMV.TAGLIST[EMV.CDOL1] = { name : "Card Risk Management Data Object List 1" };
EMV.TAGLIST[EMV.CDOL2] = { name : "Card Risk Management Data Object List 2" };

//EMV.pdol = 0x9F38179F1A0200009F33030000009F3501009F40050000000000;



/**
 * Log message if verbosity is enabled
 *
 * @param {String} msg the message to log
 */
EMV.prototype.log = function(msg) {
	if (this.verbose) {
		GPSystem.trace(msg);
	}
}



/**
 * Return cardDE
 *
 * @return the cardDE array 
 * @type Array
 */
EMV.prototype.getCardDataElements = function() {
	return this.cardDE;
}



/**
 * Send SELECT APDU
 *
 * @param {object} dfname the PSE AID
 * @param {boolean} first the selection options
 * @return the FCI
 * @type ByteString
 */
EMV.prototype.select = function(dfname, first) {
	var fci = this.card.sendApdu(0x00, 0xA4, 0x04, (first ? 0x00 : 0x02), dfname, 0x00);
	return(fci);
}



/**
 * Send READ RECORD APDU
 *
 * @param {number} sfi the Short File Identifier
 * @param {number} recno the record number
 * @return the corresponding record or empty ByteString if no data was read
 * @type ByteString
 */
EMV.prototype.readRecord = function(sfi, recno) {
	var data = this.card.sendApdu(0x00, 0xB2, recno, (sfi << 3) | 0x04, 0);
	if (this.card.SW1 == 0x6C) {
		var data = this.card.sendApdu(0x00, 0xB2, recno, (sfi << 3) | 0x04, this.card.SW2);
	}

	return(data);
}



/**
 * Create a Data Object List related ByteString
 * @param {object} dol the Data Object List
 * @return ByteString related to the DOL
 * @type ByteString
 */
EMV.prototype.createDOL = function(dol) {
	this.log("createDOL() called with " + dol.toString(HEX));
	var dolenc = new ByteBuffer();
	while (dol.length > 0) {
		var b = dol.byteAt(0);
		if ((b & 0x1F) == 0x1F) {
			var tag = dol.left(2).toUnsigned();
			var length = dol.byteAt(2);
			var	dol = dol.bytes(3);	//Remove Tag and Length Byte
		} else {
			var tag = dol.left(1).toUnsigned();
			var length = dol.byteAt(1);
			var dol = dol.bytes(2);   //Remove Tag and Length Byte 
		}
		this.log("Tag: " + tag.toString(HEX));
		var taghex = new ByteString(tag.toString(HEX), HEX);
		var addDolenc = new ByteString(this.CDOL(taghex.toString(HEX),length),HEX);
		if (typeof(addDolenc) != "undefined") {
			// ToDo: Padding
			assert(length == addDolenc.length);
			dolenc.append(addDolenc);
		}
	}
	dolenc = dolenc.toByteString();
	//print("Return this dolenc: " + dolenc);

	return(dolenc);
}



/**
 * Send GET PROCESSING OPTION APDU
 *
 * @param {ByteString} pdol the Processing Data Object List
 * @return the Application Interchange Profile and the Application File Locator
 * @type ByteString
 */
EMV.prototype.getProcessingOptions = function(pdol) {
	this.log("getProcessingOptions() called");
	
	if (pdol == null) {
		var pdol = new ByteString("8300", HEX);							// OTHER
		//var pdol = new ByteString("830B0000000000000000000000", HEX);	// VISA
		//var pdol = new ByteString("830B2028C00276160200000000", HEX);	// VISA mit generate ac support
		//var pdol = new ByteString("830B2028C00276150200000000", HEX);	
	}
	var data = this.card.sendApdu(0x80, 0xA8, 0x00, 0x00, pdol, 0, [0x9000]);

	return(data)
}



/**
 * Select and read Payment System Environment on either
 * contact or contactless card
 *
 * @param {boolean} contactless the PSE AID
 */
EMV.prototype.selectPSE = function(contactless) {
	this.log("selectPSE() called");

	this.PSE = null;
	var dfname = (contactless ? EMV.PSE2 : EMV.PSE1);
	var fci = this.select(dfname, true);
	
	//print("Card answer(HEXA) : " + fci.toString(HEX) +"\n");
	
	
	if (this.card.SW != 0x9000) {
		this.log("No PAY.SYS.DDF01 found");
		print("No PSE/PPSE found");
		return;
	}

	if (fci.length == 0) {
		this.log("No " + dfname.toString(ASCII) + " found");
		return;
	}

	print("Card answer(HEXA) : " + fci.toString(HEX) +"\n");
	// Decode FCI Template
	//var tl = new TLVList(fci, TLV.EMV);
	
	var f6 = new ASN1 (fci);
	z=f6.get(0).value;
	y=f6.get(0).tag;
	
	print("FCI Template (Tag 6F)");
	this.decodeDataElement(y,z.toString(HEX));

	
	if (contactless) {
		// Decode FCI Proprietary Template
		this.decodeDataElement(f6.get(1).tag,false);
		var a5 = new ASN1 (f6.get(1).tag, new ASN1(f6.get(1).value));
			
		this.decodeDataElement(a5.get(0).tag,false);
		var bf0c = new ASN1 (a5.get(0).tag, new ASN1(a5.get(0).value));
		
		this.decodeDataElement(bf0c.get(0).tag,false);
		// Decode FCI Issuer Discretionary Data
		var at61 = new ASN1(bf0c.getBytes().bytes(3));

		//print(at61.elements);
		
		for (var i = 0; i < at61.elements; i++) {
			t = at61.get(i).tag;
			t3 = at61.get(i).value;
			this.decodeDataElement(t,t3);
			this.log("Payment System Directory Entry:");
			this.log(t3);
			//this.PSE.push(new TLVList(t3, TLV.EMV));
		}
	} else {
		// Decode DF Name
		t = tl.index(0);

		if (t.getTag() != EMV.DFNAME) {
			throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "PSE DDF FCI Template does not contain tag 84");
		}

		// Decode FCI Proprietary Template
		t = tl.index(1);
		if (t.getTag() != EMV.FCI_ISSUER) {
			throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "PSE DDF FCI Template does not contain tag A5");
		}

		var tl = new TLVList(t.getValue(), TLV.EMV);

		// Decode SFI of the Directory Elementary File
		t = tl.index(0);
		if (t.getTag() != EMV.SFI) {
			throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "PSE DDF FCI Proprietary Template does not contain tag 88");
		}

		var sfi = t.getValue();
		assert(sfi.length == 1);
		sfi = sfi.byteAt(0);

		this.PSE = new Array();

		this.decodeFCI(fci);
				
		// Read all records from Directory Elementary File
		print("\nRead record in PSE DIR File")
		var recno = 1;
		do	{
			var data = this.readRecord(sfi, recno++);
			if (data.length > 0) {
				var tl = new TLVList(data, TLV.EMV);
				if (tl.length != 1) {
					throw new GPError("EMV", GPError.INVALID_DATA, 0, "Payment System Directory Tag 70 must contain only one entry");
				}

				var t = tl.index(0);
				if (t.getTag() != EMV.TEMPLATE) {
					throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "PSE DDF FCI Proprietary Template does not contain tag 88");
				}

				var tl = new TLVList(t.getValue(), TLV.EMV);
				
				for (var i = 0; i < tl.length; i++) {
					var t = tl.index(i);
					if (t.getTag() != 0x61) {
						throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "Payment System Directory Entry must use tag 61");
					}

					this.log("Payment System Directory Entry:");
					this.log(t.getValue());
					//this.decodeDataElement(t.getTag().toString(HEX),t.getValue().toString(HEX));
					
					
					this.PSE.push(new TLVList(t.getValue(), TLV.EMV));
				}
			this.decode6F(data);	
			}
		} while (data.length > 0);
	}
}

EMV.prototype.decode6F = function(data) {
	this.log("decodeFCI() called");
	var f6tlv = new ASN1 (data);
	var f6 = f6tlv.find(0x61);
	
	print("Application Directory Entry (Tag 61)");

	if (f6 != null) {
		for (var i = 0; i < f6.elements; i++) {
			this.cardDE[f6.get(i).tag] = f6.get(i).value;
			//this.log("Found data element " + a5.get(i).tag.toString(HEX) + " = " + a5.get(i).value.toString(HEX));
			tg=f6.get(i).tag;
			vl=f6.get(i).value;
			//print(vl.toString(HEX));
			//print(tg.toString(HEX));	
			this.decodeDataElement(tg,vl);
			//print(a5.get(i).tag.toString(HEX) + " = " + a5.get(i).value.toString(HEX) + " ... " + a5.get(i).value.toString(ASCII));
		}
	}
	//print("\nEnd of Application Directory Entry (Tag 61)\n");
}





/**
 * Return array of PSE entries or null if none defined
 * @return the PSE array
 * @type Array
 */
EMV.prototype.getPSE = function() {
	return this.PSE;
}



/**
 * Return AID of application with highest priority or null if no PSE defined
 * @return the AID
 * @type ByteString
 */
EMV.prototype.getAID = function() {
	this.log("getAID() called");

	var prio = 0xFFFF;
	var aid = null;
	var pse = this.getPSE();
	if (pse == null) {
		this.log("No PSE found");
		return null;
	}

	// Iterate through PSE entries
	for (var i = 0; i < pse.length; i++) {
		var t = pse[i].find(EMV.AID);
		if (!t) {
			throw new GPError("EMV", GPError.INVALID_DATA, 0, "Could not find an AID in PSE entry");
		}
		var entryAid = t.getValue();

		var entryPrio = 0xFFFE;
		var t = pse[i].find(EMV.PRIORITY);
		if (t != null) {
			entryPrio = t.getValue().toUnsigned();
			entryPrio &= 0x0F;
		}
		if (entryPrio < prio) {
			prio = entryPrio;
			aid = entryAid;
		}
	}
	print(aid);
	return aid;
}



/**
 * Select application and return FCI
 * @param {ByteString} aid the Application Identifier
 */
EMV.prototype.selectADF = function(aid) {
	this.log("selectADF() called");
	var fci = this.select(aid, true);
	print("Card answer(HEXA) : " + fci.toString(HEX) + "\n");
	if (this.card.SW != 0x9000) {
		throw new GPError("EMV", GPError.INVALID_DATA, 0, "Could not select ADF with AID " + aid.toString(HEX));
	}
	this.decodeFCI(fci);
	this.cardDE[EMV.AID] = aid;
}



/**
 * Decode the A5 Template from the FCI
 * @param {ByteString} fci the File Control Informations
 */
EMV.prototype.decodeFCI = function(fci) {
	this.log("decodeFCI() called");

	var fcitlv = new ASN1(fci);
	var a5 = fcitlv.find(0xA5);

	print("\nFCI Proprietary Template (Tag A5)");

	if (a5 != null) {
		for (var i = 0; i < a5.elements; i++) {
			this.cardDE[a5.get(i).tag] = a5.get(i).value;
			tg=a5.get(i).tag;
			vl=a5.get(i).value;
			this.decodeDataElement(tg,vl);
			
			if(tg == 0xBF0C){
				var bf = a5.get(i).getBytes();
				var bf0c = new ASN1(bf);
				for (var b = 0; b < bf0c.elements; b++) {
				this.cardDE[bf0c.get(b).tag] = bf0c.get(b).value;
				tg1=bf0c.get(b).tag;
				vl1=bf0c.get(b).value;
				this.decodeDataElement(tg1,vl1);
				}
			}
			
		}
	}
	//print("\nEnd of FCI Proprietary Template (Tag A5) \n");
}

EMV.prototype.decodeDataElement = function(tag, value) {
t.decodeDE(tag,value);
}












/**
 * Try a list of predefined AID in order to select an application
 */
EMV.prototype.tryAID = function() {
	this.log("tryAID() called");

	for (var i = 0; i < EMV.AIDLIST.length; i++) {
		var le = EMV.AIDLIST[i];
		var aid = new ByteString(le.aid, HEX);
		var fci = this.select(aid, true);
		
		if (fci.length > 0) {
			this.cardDE[EMV.AID] = aid;
			this.decodeFCI(fci);
		}
	}
}



/**
 * Add elements from ByteString into the cardDE array
 * @param {TLVList} tlvlist
 */
EMV.prototype.addCardDEFromList = function(tlvlist) {
	this.log("addCardDEFromList() called");
	
	for (var i = 0; i < tlvlist.length; i++) {
		var t = tlvlist.index(i);

		if (t.getTag() != 0) {
			this.cardDE[t.getTag()] = t.getValue();
			this.decodeDataElement(t.getTag(),t.getValue());
		}
	}
	
	return
}



/**
 * Inform the ICC that a new transaction is beginning.
 * Store AIP and AFL into the cardDE array.
 */
EMV.prototype.initApplProc = function() {
	this.log("initApplProc() called");

	var pdol = this.cardDE[EMV.PDOL];
	var pdolenc = null;
	
	if (typeof(pdol) != "undefined") {
		pdolenc = this.createDOL(pdol);
		var length = pdolenc.length
		var length = length.toString(HEX);
		if (pdolenc.length <= 0xF) {
			length = "0".concat(length);
		}
		var length = new ByteString(length, HEX);
		pdolenc = new ByteString("83", HEX).concat(length).concat(pdolenc);
		//print(pdolenc);
	}

	var data = this.getProcessingOptions(pdolenc);
	print("Card answer(HEXA) :  " + data.toString(HEX) + "\n");
	var tl = new TLVList(data, TLV.EMV);
	if (tl.length != 1) {
		throw new GPError("EMV", GPError.INVALID_DATA, 0, "Invalid format in GET PROCESSING OPTIONS response");
	}

	var t = tl.index(0);
	if (t.getTag() == EMV.RMTF1) {	// Format 1
		this.cardDE[EMV.AIP] = t.getValue().left(2);
		this.cardDE[EMV.AFL] = t.getValue().bytes(2);
		
		this.decodeDataElement(0x82,t.getValue().left(2));
		this.decodeDataElement(0x94,t.getValue().bytes(2));
		
		//print("AIP ...\n" + t.getValue().left(2) + "\n");
		//print("AFL ...\n" + t.getValue().bytes(2) + "\n");
		
	} else if (t.getTag() == EMV.RMTF2) {
		tl = new TLVList(t.getValue(), TLV.EMV);
		if (tl.length < 2) {
			throw new GPError("EMV", GPError.INVALID_DATA, 0, "At least two entries tag 77 of GET PROCESSING OPTIONS response expected");
		}
		this.addCardDEFromList(tl);
		
		
	} else {
		throw new GPError("EMV", GPError.INVALID_DATA, 0, "Invalid tag in GET PROCESSING OPTIONS response");
	}
}



/**
 * Read application data as indicated in the Application File Locator.
 * Collect input to data authentication.
 *
 */
EMV.prototype.readApplData = function() {
	//print("<-----Read application data as indicated in the Application File Locator.------");
	//print("---------------------Collect input to data authentication.---------------------");
	// Application File Locator must exist
	assert(typeof(this.cardDE[EMV.AFL]) != "undefined");
	var afl = this.cardDE[EMV.AFL];
	
	//print("Application File Locator" + "  -  " + afl + "\n\n");
	
	
	// Must be a multiple of 4
	assert((afl.length & 0x03) == 0);

	// Collect input to data authentication	
	var da = new ByteBuffer();

	while(afl.length > 0) {
		var sfi = afl.byteAt(0) >> 3;	// Short file identifier
		var srec = afl.byteAt(1);	// Start record
		var erec = afl.byteAt(2);	// End record
		var dar = afl.byteAt(3);	// Number of records included in data authentication

		for (; srec <= erec; srec++) {
			// Read all indicated records
			var data = this.readRecord(sfi, srec);
			print("-------------------------------------------------------------------------------------------------------");
			print("SFI  " + sfi + "  Record No. " + srec);
			print("-------------------------------------------------------------------------------------------------------");
			//print(data);

			// Decode template
			var tl = new TLVList(data, TLV.EMV);
			assert(tl.length == 1);
			var t = tl.index(0);
			//print(t.getTag(),t.getValue());
			this.decodeDataElement(t.getTag(),t.getValue());
			
			var tlv = new ASN1(data);
			
			//print(tlv);
			
			if (tlv != null) {
				for (var i = 0; i < tlv.elements; i++) {
					this.cardDE[tlv.get(i).tag] = tlv.get(i).value;
					//this.log("Found data element " + a5.get(i).tag.toString(HEX) + " = " + a5.get(i).value.toString(HEX));
					tg=tlv.get(i).tag;
					vl=tlv.get(i).value;
					//print(vl.toString(HEX));
					//print(tg.toString(HEX));	
					this.decodeDataElement(tg,vl);
					//print(a5.get(i).tag.toString(HEX) + " = " + a5.get(i).value.toString(HEX) + " ... " + a5.get(i).value.toString(ASCII));
				}
			}
			
			
			
			
			
			
			assert(t.getTag() == EMV.TEMPLATE);
			
			// Add data authentication input			
			if (dar > 0) {
				if (sfi <= 10) {	// Only value
					da.append(t.getValue());
				} else {		// Full template
					da.append(data);
				}
				dar--;
			}

			// Add card based data elements	to internal list
			var tl = new TLVList(t.getValue(), TLV.EMV);
			this.addCardDEFromList(tl);
		}

		// Continue with next entry in AFL
		afl = afl.bytes(4);
	}
	this.daInput = da.toByteString();
	print("\nData Authentication Input: " + this.daInput.toString(HEX));
	print("------------------------------------------------------------------------------>\n");
}



/**
 * Return the Data Authentication Input
 * @return the Data Authentication Input
 * @type ByteString
 */
EMV.prototype.getDAInput = function() {
	return this.daInput;
}



/**
 * Send GENERATE APPLICATION CRYPTOGRAM APDU
 */
EMV.prototype.generateAC = function(iccPublicKeyModulus,l) {
	/*
	p1
	0x00 = AAC = reject transaction
	0x40 = TC = proceed offline
	0x80 = ARQC = go online
	*/
	/*
	var p1 = 0x80;
	
		
	var unpredictableNumber = this.terminalDE[EMV.UN]; //9F37
		
	//CDOL1 from terminal resident data
	
	var CDOL1 = this.cardDE[0x8C].toString(HEX);
	
	var TagList2 = ["9A","9C","95"];
	var TagList4 = ["9F02","9F03","9F1A","5F2A","9F37","9F35","9F45","9F4C","9F34","9F21","9F7C"];


	var parsed = "";

	for(var i=0; i < CDOL1.length; i++){
	var found = false;
	// Busca un tag de 2 bytes
	var compare = CDOL1.substr(i,2);
		for(tag in TagList2){
			if(!found){
				if(TagList2[tag] == compare){
					found = true;
					CDOL1.substr(i+2,2);
					parsed += this.CDOL(TagList2[tag],CDOL1.substr(i+2,2));
				}
			}
		}
		// Si tiene que buscar un tag de 4 bytes
		compare = CDOL1.substr(i,4);
		for(tag in TagList4){
			if(!found){
				if(TagList4[tag] == compare){
					found == true;
					CDOL1.substr(i+4,2);
					parsed += this.CDOL(TagList4[tag],CDOL1.substr(i+4,2));
				}
			}
		}
	}



	
	//First Generate AC
	print("======================================================================================");
	print("FIRST GENERATE AC");
	print("======================================================================================");
	
	print("1st Generate AC\n" + "CDOL1 = " + this.cardDE[0x8C].toString(HEX));
	
	print("Terminal Input: " + parsed.toString(HEX));
	
	var Data = new ByteString(parsed,HEX);
	
	var generateAC = card.sendApdu(0x80, 0xAE, p1, 0x00, Data, 0x00);	 //First Generate AC
	print("Card answer(HEXA) : " + generateAC.toString(HEX));
	
	print("Data returned by command using Format 1");
	var CID = generateAC.bytes(2,1);
	var ATC = generateAC.bytes(3,2);
	var AppCrypto = generateAC.bytes(5,8);
	var IAD = generateAC.bytes(13,7);
	
	this.decodeDataElement(0x9F27,CID);
	this.decodeDataElement(0x9F36,ATC);
	this.decodeDataElement(0x9F26,AppCrypto);
	this.decodeDataElement(0x9F10,IAD);
	
		
	// CDA Validation - If P1=90 in First Gen AC command.
	if(p1 == 0x90){
	
		//CDA Validation
		print("======================================================================================");
		print("COMBINED DYNAMIC DATA AUTHENTICATION - APPLICATION CRYPTOGRAM (CDA)");
		print("======================================================================================");
	
		var picKey = new Key();
		picKey.setType(Key.PUBLIC);
		picKey.setComponent(Key.MODULUS, iccPublicKeyModulus2);
		picKey.setComponent(Key.EXPONENT, this.cardDE[0x9F47]);
		var decryptedSDAD = crypto.decrypt(picKey, Crypto.RSA, this.cardDE[0x9F4B]);
	
		var SDAD = this.cardDE[0x9F4B];
		var SDADlength = SDAD.length;
		
		print("Signed Dynamic Application Data (in clear)....." + decryptedSDAD.toString(HEX));
	
	
		// Step 1: SDAD and ICC Public Key Modulus have the same length
		assert( SDADlength == iccPublicKeyModulus2.length);
		print("ICC Public Key Modulo length " + iccPublicKeyModulus2.length + " is equal to Signed Dynamic Application Data length " + SDADlength + "\n");
		// Step 2: The Recovered Data Trailer is equal to 'BC'
		assert(decryptedSDAD.byteAt(decryptedSDAD.length - 1) == 0xBC);
		print("The Recovered Data Trailer is equal to 'BC'");
		// Step 3: The Recovered Data Header is equal to '6A'
		assert(decryptedSDAD.byteAt(0) == 0x6A);
		print("The Recovered Data Header is equal to '6A'");
		// Step 4: The Signed Data Format is equal to '05'
		assert(decryptedSDAD.byteAt(1) == 0x05);
		print("Certificate Format is equal to '05'");
	
		print("Retrieval of ICC Dynamic Data");
		var iccDDlength = decryptedSDAD.byteAt(3);
		var iccDD = decryptedSDAD.bytes(4,iccDDlength); //Retrieval of ICC Dynamic Data
		var ICCDNlength = iccDD.byteAt(0); //ICC Dynamic Number Length
		print("ICC Dynamic Number Length:" + ICCDNlength.toString(HEX));
		var ICCDN = iccDD.bytes(1,ICCDNlength); //ICC Dynamic Number
		print("ICC Dynamic Number:" + ICCDN.toString(HEX));
		var CryptoID = iccDD.byteAt(ICCDNlength + 1); //Cryptogram Information Data
		print("Cryptogram Information Data" + CryptoID.toString(HEX));
		var Cryptogram = iccDD.bytes(ICCDNlength + 2,08); //TC or ARQC
		print("TC or ARQC: " + Cryptogram.toString(HEX));
		var TraDHash = iccDD.bytes(ICCDNlength + 0x0A, iccDDlength - (ICCDNlength + 0x0A)); //Transaction Data Hash Code   
		print("Transaction Data Hash Code: " + TraDHash.toString(HEX));
	
		var CID = GenAC.get(0);
		var CID2 = new ByteString(CID.getBytes(),HEX);
		var AppTCount = GenAC.get(1);
		var AppTCount2 = new ByteString(AppTCount.getBytes(),HEX);
		var issappda = GenAC.get(3);
		var issappda2 = new ByteString(issappda.getBytes(),HEX);	
	
	
		assert(CryptoID.toString(HEX) ==  GenAC.get(0).value);
		
		print("Cryptogram Information Data " + CryptoID.toString(HEX) + " in ICC Dynamic Data identical to the value retrieved in GENERATE AC response");
		
		var PP = SDADlength - iccDDlength - 0x19;
		var longi = iccDDlength + 4 + PP;
		var HashRecovered = decryptedSDAD.bytes(longi,0x14); //Recovered Hash
		
		var bufferSign = (decryptedSDAD.bytes(01,03 + iccDDlength + PP)).concat(unpredictableNumber);
		print("Buffer for Hash Verification (Signature): " + bufferSign.toString(HEX));
		
		
		var hashsign = this.crypto.digest(Crypto.SHA_1, bufferSign);
		print("Hash Result: " + hashsign.toString(HEX)); // Hash calculated. 
			
		assert(hashsign.toString(HEX) == HashRecovered.toString(HEX));
		
		print("The calculated Hash result is equal to the recovered Hash result");
		
		var pdol = this.cardDE[0x9F38];
		if(pdol != undefined){
			var bufferTrans = pdol.concat(Data);
		}
		else{
			var bufferTrans = Data.concat(CID2).concat(AppTCount2).concat(issappda2);
		}
	
		print("Buffer for Hash Verification (Transaction Data): " + bufferTrans.toString(HEX))
		
		var hashtrans = this.crypto.digest(Crypto.SHA_1, bufferTrans);
		print("Hash Result: " + hashtrans.toString(HEX)); // Hash calculated. 
		
		assert(hashtrans.toString(HEX) == TraDHash.toString(HEX))
		print("The calculated Hash result is equal to the recovered Hash result");
		print("Combined Dynamic Data Authentication verification - OK\n");
	}
	*/
	var valid	= this.CryptoValidation();
	var MAC = valid[0];
	var ARPC = valid[1];
	var DKac = valid[2]
	var DKsmi = valid[3];
	var DKsmc = valid[4];
	
	//var cryptoauth = this.cardDE[0x9F26];
		if(MAC.toString(HEX) == this.cardDE[0x9F26].toString(HEX)){
			print("Successful Cryptogram Verification ")
		}else{
			print("Unsuccessful Cryptogram Verification ")
		}	
	return;
	
}

EMV.prototype.secondgenerateAC = function(gram,rescrypto){
	//Second Generate AC
		print("======================================================================================");
		print("SECOND GENERATE AC");
		print("======================================================================================");
		
		var CDOL2 = this.cardDE[0x8D].toString(HEX);
		
		print("2nd Generate AC\n" + "CDOL2 = " + CDOL2.toString(HEX));
		
		var TagList2 = ["9A","9C","95","91","8A"];
		var TagList4 = ["9F02","9F03","9F1A","5F2A","9F37","9F35","9F45","9F4C","9F34"];


		var parsed = "";

		for(var i=0; i < CDOL2.length; i++){
		var found = false;
		// Busca un tag de 2 bytes
		var compare = CDOL2.substr(i,2);
			for(tag in TagList2){
				if(!found){
					if(TagList2[tag] == compare){
						found = true;
						CDOL2.substr(i+2,2);
						parsed += this.CDOL(TagList2[tag],CDOL2.substr(i+2,2));
					}
				}
			}
			// Si tiene que buscar un tag de 4 bytes
			compare = CDOL2.substr(i,4);
			for(tag in TagList4){
				if(!found){
					if(TagList4[tag] == compare){
						found == true;
						CDOL2.substr(i+4,2);
						parsed += this.CDOL(TagList4[tag],CDOL2.substr(i+4,2));
					}
				}
			}
		}
		
		print("Terminal Input: " + parsed.toString(HEX));
		
		var Data = new ByteString(parsed,HEX);
		var p1 = 0x40;
		
		var generateAC = card.sendApdu(0x80, 0xAE, p1, 0x00, Data, 0x00);	 //First Generate AC
		print("Card answer(HEXA) : " + generateAC.toString(HEX));

		print("Data returned by command using Format 1");
		var CID = generateAC.bytes(2,1);
		var ATC = generateAC.bytes(3,2);
		var AppCrypto = generateAC.bytes(5,8);
		var IAD = generateAC.bytes(13,7);
		
		this.decodeDataElement(0x9F27,CID);
		this.decodeDataElement(0x9F36,ATC);
		this.decodeDataElement(0x9F26,AppCrypto);
		this.decodeDataElement(0x9F10,IAD);
		
		
		var valid	= this.CryptoValidation(generateAC);
		var MAC = valid[0];
		

		if(MAC.toString(HEX) == AppCrypto.toString(HEX)){
			print("Successful Cryptogram Verification ")
		}else{
			print("Unsuccessful Cryptogram Verification ")
		}	
}

EMV.prototype.CryptoValidation = function(generateAC){
	print("======================================================================================");
	print("APPLICATION CRYPTOGRAM VERIFICATION");
	print("======================================================================================");
	
	//IMK - Master Keys
	
	var keyac = new ByteString(PARAMETERS.KEY_AC,HEX);
	var Keysmi = new ByteString(PARAMETERS.KEY_SMC,HEX);
	var keysmc = new ByteString(PARAMETERS.KEY_SMI,HEX);
	print("MKac= " + keyac.toString(HEX));
	print("MKsmi= " + Keysmi.toString(HEX));
	print("MKsmc= " + keysmc.toString(HEX));
	var PANumber = this.cardDE[0x57].bytes(0,8);
	var PSN = this.cardDE[0x5F34];
	var unpredictableNumber = this.terminalDE[EMV.UN];
	
	
	//PAN|PSN
	
	var block = PANumber.concat(PSN);
	print("PAN|PSN : " + block.toString(HEX));
	var block2 = block.bytes(1);
	print("Input Data Block A = " + block2.toString(HEX));
	
	var l = block2.length;
	
	var F = new ByteString("0xFF",HEX);
	var k;
	
	var z = block2.byteAt(0);
	k1 = F.add(-z);
	var f = new ByteBuffer(k1,HEX);
	
	for(var i = 1;i<l;i++){
		var x = block2.byteAt(i);	
		k2 = F.add(-x);
		k3 = new ByteBuffer(k2,HEX);
		f.insert(i,k3);
	}

	blockf = block2.toString(HEX).concat(f.toString(HEX));
	print("Input Data Block B = " + f.toString(HEX) +" (Invert A)");
		
	//Derived Master Keys
	
	var chiper = new ByteString(blockf, HEX);
	
	var MKac = new Key();
	MKac.setComponent(Key.DES,keyac);
	
	var MKsmi = new Key();
	MKsmi.setComponent(Key.DES,Keysmi);
	
	var MKsmc = new Key();
	MKsmc.setComponent(Key.DES,keysmc);
	
	
	var DKac = crypto.encrypt(MKac,Crypto.DES_ECB,chiper);
	var DKsmi = crypto.encrypt(MKsmi,Crypto.DES_ECB,chiper);
	var DKsmc = crypto.encrypt(MKsmc,Crypto.DES_ECB,chiper);
	
	
	print("DKac = 3DES_ECB(MKac)[Input Data Block A|Input Data Block B] = " + DKac.toString(HEX));
	print("DKsmi = 3DES_ECB(MKac)[Input Data Block A|Input Data Block B] = " + DKsmi.toString(HEX));
	print("DKsmc = 3DES_ECB(MKac)[Input Data Block A|Input Data Block B] = " + DKsmc.toString(HEX));
	
	var DKac2 = new Key();
	DKac2.setComponent(Key.DES,DKac);
	
	
	//Initial Buffer for Cryptogram calculation 
	
	print("Input Data Elements to Cryptogram=AMOUNT AUTHORIZED|AMOUNT OTHER|TERMINAL COUNTRY CODE|TVR|TXN CURRENCY CODE|TXN DATE|TXN TYPE|UN|AIP|ATC|CVR");
	
	var amountauth = this.CDOL("9F02");
	var amountoth = this.CDOL("9F03");
	var termcoun = this.CDOL("9F1A");
	var tvr = this.CDOL("95");
	var transcurren = this.CDOL("5F2A");
	var txdate = this.CDOL("9A");
	var txtype = this.CDOL("9C");
	var unprenum = this.CDOL("9F37");
	var aip = this.cardDE[0x82];
	var ATC1 = this.cardDE[0x9F36];
	var iad = this.cardDE[0x9F10];
	var CVR = iad.bytes(3,4);
	var DE1 = amountauth.concat(amountoth)
	var DE2 = DE1.concat(termcoun);
	var DE3 = DE2.concat(tvr)
	var DE4 = DE3.concat(transcurren);
	var DE5 = DE4.concat(txdate);
	var DE6 = DE5.concat(txtype);
	var DE7 = DE6.concat(unprenum);
	var DE8 = DE7.concat(aip);
	var DE9 = DE8.concat(ATC1);
	var DE10 = DE9.concat(CVR);
	//var DE11 = DE10.toString(HEX).concat("80");

	var Dkac2DES = new Key();
	Dkac2DES.setComponent(Key.DES,DKac.bytes(0,8));
	
	var DE11 = new ByteString(DE10,HEX);
	
	//validar que la longitud del buffer es multiplo de 8
	
	var DE11long = DE11.length;
	var modulo = DE11long%8;
	//print(modulo);
	var Tag2 = "00";
	var x = 1;
	while(x < parseInt(8 - modulo)){
	Tag2 += "00";
	x++
	} 
	
	var DE12 = new ByteString(DE11 + Tag2,HEX);
		
	print("Input Data to Cryptogram = " + DE12.toString(HEX) + "\n"); 
	
	var B1 = new ByteString("0000000000000000",HEX);
	
	for(var x=0;x<DE12.length;x+=8){
		var B2 = DE12.bytes(x,8);
		var B3 = B1.xor(B2);
	
		print("B1[" + B1.toString(HEX) + "] " + "XOR " + "B2[" + B2.toString(HEX) + "] " + "=" + "B3[" + B3.toString(HEX) + "]");
	
		B1 = crypto.encrypt(Dkac2DES,Crypto.DES_ECB,B3);
		
		if(x<(DE12.length - 8)){
			print("DES([" + DKac.bytes(0,8).toString(HEX) + "], B3[" + B3.toString(HEX) + "]) = [" + B1.toString(HEX) + "] = Next B1" );
		}
	}

	var MAC = crypto.encrypt(DKac2,Crypto.DES_ECB,B3); //Cryptogram value calculated 
	print("MAC Cryptogram = " + MAC.toString(HEX));

	var ARPCResCod = this.issuerDE[0x1F68].toString(HEX);
	var t1 = new ByteString(ARPCResCod.concat("000000000000"),HEX);
	var t2 = new ByteString(MAC,HEX);
	
	var ARPCResCod2 = t2.xor(t1);
	var ARPC = crypto.encrypt(Dkac2DES,Crypto.DES_ECB,ARPCResCod2);

	return [MAC,ARPC,DKac,DKsmi,DKsmc];//datos
	
}

EMV.prototype.Appblock = function(DKsmi,DKsmc){

	print("======================================================================================");
	print("APPLICATION BLOCK");
	print("======================================================================================");

	var Session = this.SessionIntegrity(DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var dataMAC = new ByteString("841E000008",HEX);
	var ATC = new ByteString(ATransCount.bytes(3,2),HEX);
	var MAC = new ByteString(mac,HEX);
	
	var data = dataMAC.concat(ATC).concat(MAC) + "80";
	var data2 = new ByteString(data,HEX);
	print("Input Data to MAC=" + data2.toString(HEX));
	
	var dataMAC = crypto.sign(sKsmi2, Crypto.DES_MAC_EMV,data2);
	
	print("MAC(SKsmi)[MAC Input Data]=" + dataMAC.toString(HEX));
	var cardblock = card.sendApdu(0x84, 0x1E, 0x00, 0x00, dataMAC);
	
	print("Increment ARQC by 1 = " + newmac.toString(HEX));
	
	print("<send> 84 1E 00 00 08 " + dataMAC);
	
	print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	
	return newmac;
}


EMV.prototype.AppUnblock = function(DKsmi,DKsmc){

	print("======================================================================================");
	print("APPLICATION UNBLOCK");
	print("======================================================================================");

	var Session = this.SessionIntegrity(DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var dataMAC = new ByteString("8418000008",HEX);
	var ATC = new ByteString(ATransCount.bytes(3,2),HEX);
	var MAC = new ByteString(mac,HEX);
	
	var data = dataMAC.concat(ATC).concat(MAC) + "80";
	var data2 = new ByteString(data,HEX);
	print("Input Data to MAC=" + data2.toString(HEX));
	
	var dataMAC = crypto.sign(sKsmi2, Crypto.DES_MAC_EMV,data2);
	
	print("MAC(SKsmi)[MAC Input Data]=" + dataMAC.toString(HEX));
	var cardblock = card.sendApdu(0x84, 0x18, 0x00, 0x00, dataMAC);
	
	print("Increment ARQC by 1 = " + newmac.toString(HEX));
	
	print("<send> 84 18 00 00 08 " + dataMAC);
	
	print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	
	return newmac;
}


EMV.prototype.PinUnblock = function(DKsmi,DKsmc){

	print("======================================================================================");
	print("PIN UNBLOCK");
	print("======================================================================================");

	var Session = this.SessionIntegrity(DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var dataMAC = new ByteString("8424000008",HEX);
	var ATC = new ByteString(ATransCount.bytes(3,2),HEX);
	var MAC = new ByteString(mac,HEX);
	
	var data = dataMAC.concat(ATC).concat(MAC) + "80";
	var data2 = new ByteString(data,HEX);
	print("Input Data to MAC=" + data2.toString(HEX));
	
	var dataMAC = crypto.sign(sKsmi2, Crypto.DES_MAC_EMV,data2);
	
	print("MAC(SKsmi)[MAC Input Data]=" + dataMAC.toString(HEX));
	var cardblock = card.sendApdu(0x84, 0x24, 0x00, 0x00, dataMAC);
	
	print("Increment ARQC by 1 = " + newmac.toString(HEX));
	
	print("<send> 84 24 00 00 08 " + dataMAC);
	
	print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	
	return newmac;


}


EMV.prototype.PinChange = function(DKac,DKsmi,DKsmc){
	print("======================================================================================");
	print("PIN CHANGE");
	print("======================================================================================");

	var Session = this.SessionIntegrity(DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	var sKsmc = Session[2];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var sKsmc2 = new Key();
	sKsmc2.setComponent(Key.DES,sKsmc);
	
	print("SKsmc = 3DES_ECB(DKsmc)[Input Data Block A|Input Data Block B] = " + sKsmc.toString(HEX) + "\n");
	
	var PIN = new ByteString("9876",HEX);
	var UDKA = new ByteString(DKac.bytes(4,4),HEX);
	var PINData1 = new ByteString("00000000" + UDKA,HEX);
	var PINData2 = new ByteString("04" + PIN + "FFFFFFFFFF",HEX);
	
	print("PIN=" + PIN.toString(HEX));
	print("PIN Data 1=" + PINData1.toString(HEX));
	print("PIN Data 2=" + PINData2.toString(HEX));
	
	var PINData = PINData1.xor(PINData2);
	print("PIN Data =" + PINData.toString(HEX))
	
	var PINblock = new ByteString("80" + PINData + "80000000000000",HEX);
	
	var EncrypPIN = crypto.encrypt(sKsmc2,Crypto.DES_ECB,PINblock);
	print("Encrypted PIN Block=3DES_ECB(SKsmc)[PIN Block]=" + EncrypPIN.toString(HEX));
	
	var dataMAC = new ByteString("8424000218",HEX);
	var ATC = new ByteString(ATransCount.bytes(3,2),HEX);
	var MAC = new ByteString(mac,HEX);
	var EncPIN = new ByteString(EncrypPIN,HEX);
	
	var data = dataMAC.concat(ATC).concat(MAC).concat(EncPIN) + "80";
	var data2 = new ByteString(data,HEX);
	print("Input Data to MAC=" + data2.toString(HEX));
	
	var dataMAC = crypto.sign(sKsmi2, Crypto.DES_MAC_EMV,data2);
	print("MAC(SKsmi)[MAC Input Data]=" + dataMAC.toString(HEX));
	
	var Datacommand = new ByteString(EncPIN + dataMAC,HEX);
	
	var cardblock = card.sendApdu(0x84, 0x24, 0x00, 0x02, Datacommand);
	
	print("Increment ARQC by 1 = " + newmac.toString(HEX));
	
	print("<send> 84 24 00 02 18 " + Datacommand);
	
	print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	
	return newmac;

}


EMV.prototype.SessionIntegrity = function(DKsmi,DKsmc){
	
	var ATC = new ByteString(ATransCount.bytes(3,2),HEX);
	var rest = ATC.neg().add(-1);
	var blockA = new ByteString("000000000000",HEX).concat(ATC);
	var blockB = new ByteString("000000000000",HEX).concat(rest);
	print("Input Data Block A to SKsmi=" + blockA.toString(HEX));
	print("Input Data Block A to SKsmi=" + blockB.toString(HEX));
	
	var block = blockA.concat(blockB);
	var sKsmi = DKsmi.xor(block);
		
	print("SKsmi = 3DES_ECB(DKsmi)[Input Data Block A|Input Data Block B] = " + sKsmi.toString(HEX) + "\n")
	
	var sKsmc = DKsmc.xor(block);
	
	//var newmac = new ByteString(mac,HEX);
	var newmac = mac.add(1);
	
	return [sKsmi,newmac,sKsmc];
}



EMV.prototype.CDOL = function(tag1,l1){
	var l = parseInt(l1,16);
	switch (tag1) {
		case "91":
			var firstGAC = arpc.concat(this.issuerDE[0x1F68]);
			return firstGAC.toString(HEX);
			break;
		case "8A":
			var AurespCode = this.issuerDE[0x8A];
			return AurespCode.toString(HEX);
			break;
		case "9A":
			var TransDate = this.terminalDE[0x9A];
			return TransDate.toString(HEX);
			break;
		case "9C":
			var TransType = this.terminalDE[0x9C];
			return TransType.toString(HEX);
			break;
		case "95":
			var TVR = new ByteString("0000000000",HEX);
			return TVR.toString(HEX);
			break;
		case "9F02":
			var amount = this.terminalDE[0x9F02];
			return amount.toString(HEX);
			break;
		case "9F03":
			var amountother = this.terminalDE[0x9F03];
			return amountother.toString(HEX);
			break;
		case "9F1A":
			var TermCC = this.terminalDE[0x9F1A];
			return TermCC.toString(HEX);
			break;
		case "5F2A":
			var TransCC = this.terminalDE[0x5F2A];
			return TransCC.toString(HEX);
			break;
		case "9F37":
			var unpredictableNumber1 = this.terminalDE[EMV.UN];
			return unpredictableNumber1.toString(HEX);
			break;
		case "9F35":
			var terminaltype = this.terminalDE[0x9F35];
			return terminaltype.toString(HEX);
			break;
		case "9F45":
			var DataAuthCode = this.terminalDE[0x9F45];
			return DataAuthCode.toString(HEX);
			break;
		case "9F4C":
			var iccDynamicNumber2 = iccDynamicNumber;
			return iccDynamicNumber2.toString(HEX);
			break;
		case "9F34":
			var CVMResults = this.terminalDE[0x9F34];
			return CVMResults.toString(HEX);
			break;
		case "9F66":
			var TTQ = this.terminalDE[0x9F66];
			return TTQ.toString(HEX);
			break;
		default:
			var Tag2 = "00";
			var x = 1;
			while(x < parseInt(l1)){
			Tag2 += "00";
			x++
			} 
			return(Tag2)
			break;				 
		}
}
