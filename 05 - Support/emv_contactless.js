/**
 *
 *	This software is based on the Smart Card Shell 3, found on https://www.openscdp.org/scsh3/
 *
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 * 	The autoVTP software by Gemalto has the authors:
 *	Bastidas, Luis Eduardo
 *	Viotti Bozzini, Augusto
 *	Zarza, Ezequiel Martin
 *
 * @fileoverview The EMV class contains necessary functions for transaction processing
 */


 /*
 *		Depending on which action needs to be performed, throws will be present all over the document 
 *		with the purpose of this file being the base execution file
 *
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

	this.terminalDE[EMV.UN] = crypto.generateRandom(4);

	this.terminalDE[0x9F33] = new ByteString("2028C0", HEX);
	this.terminalDE[0x9F1A] = new ByteString("0032", HEX);
	this.terminalDE[0x9F35] = new ByteString("15", HEX);
	this.terminalDE[0x9F40] = new ByteString("0200000000", HEX);

	this.issuerDE = new Array();
	this.issuerDE[0x8A] = new ByteString("3030", HEX); //Authorization Response Code
	this.issuerDE[0x1F68] = new ByteString("0010", HEX); //Internal Tag - Authorization Response Cryptogram 
	
	this.verbose = false;
}



// Constants

var testing_UnpredNumber=true;

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
	return fci;
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
		var addDolenc = this.terminalDE[tag];
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

	return(data);
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
	
	print("Card answer(HEXA) : " + fci.toString(HEX) +"\n");
	
	
	if (this.card.SW != 0x9000) {
		this.log("No PAY.SYS.DDF01 found");
		return;
	}

	if (fci.length == 0) {
		this.log("No " + dfname.toString(ASCII) + " found");
		return;
	}

	// Decode FCI Template
	var tl = new TLVList(fci, TLV.EMV);
	
	var f6 = new ASN1 (fci);
	z=f6.get(0).value;
	y=f6.get(0).tag;
	print("FCI Template (Tag 6F)");
	this.decodeDataElement(y,z.toString(HEX));
	
	var t = tl.index(0);
	if (t.getTag() != EMV.FCI) {
		throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "FCI does not contain tag 6F");
	}

	var tl = new TLVList(t.getValue(), TLV.EMV);
	if (tl.length < 2) {
		throw new GPError("EMV", GPError.INVALID_DATA, 0, "FCI must contain at least two elements");
	}

	if (contactless) {
		// Decode FCI Proprietary Template
		t = tl.find(EMV.FCI_ISSUER);
		if (!t) {
			throw new GPError("EMV", GPError.INVALID_DATA, 0, "Could not find FCI Proprietary Template in FCI");
		}

		var tl = new TLVList(t.getValue(), TLV.EMV);
		if (tl.length < 1) {
			throw new GPError("EMV", GPError.INVALID_DATA, 0, "FCI Proprietary Template does not contains any objects");
		}

		// Decode FCI Issuer Discretionary Data
		t = tl.index(0);
		if (t.getTag() != EMV.FCI_ISSUER_DISCRETIONARY_DATA) {
			throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "FCI does not contain FCI Issuer Discretionary Data (BF0C)");
		}

		tl = new TLVList(t.getValue(), TLV.EMV);

		this.PSE = new Array();

		for (var i = 0; i < tl.length; i++) {
			t = tl.index(i);
			if (t.getTag() != EMV.DIRECTORY_ENTRY) {
				throw new GPError("EMV", GPError.INVALID_DATA, t.getTAG(), "FCI Issuer Discretionary Data does not contain a valid entry with tag 61");
			}
			this.log("Payment System Directory Entry:");
			this.log(t.getValue());
			this.PSE.push(new TLVList(t.getValue(), TLV.EMV));
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
		
		if(ApplicationUnblock){
			print("Could not select ADF with AID " + aid.toString(HEX));
			return;
		}
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
	switch (tag) {
		case 0x9F6C:
			print("MagStripe Application Version Number - (9F6C): " + value.toString(HEX));
			break;
		case 0x9F62:
			print("Track 1 Bit Map for CVC3 (PCVC3_track1) - (9F62): " + value.toString(HEX));
			break;
		case 0x9F63:
			print("Track 1 Bit Map for UN and ATC (PUNATC_track1) - (9F63): " + value.toString(HEX));
			break;
		case 0x56:
			print("Track 1 Data - (56): " + value.toString(HEX));
			break;
		case 0x9F64:
			print("Track 1 Number of ATC Digits (NATC_track1) - (9F64): " + value.toString(HEX));
			break;
		case 0x9F65:
			print("Track 2 Bit Map for CVC3 (PCVC3_track2) - (9F65): " + value.toString(HEX));
			break;
		case 0x9F66:
			print("Track 2 Bit Map for UN and ATC (PUNATC_track2) - (9F66): " + value.toString(HEX));
			break;
		case 0x9F6B:
			print("Track 2 Data - (9F6B): " + value.toString(HEX));
			break;
		case 0x9F67:
			print("Track 2 Number of ATC Digits (NATC_track2) - (9F67): " + value.toString(HEX));
			break;
		case 0x9F4A:
			print("Static Data Authentication Tag List - (9F4A): " + value.toString(HEX));
			break;
		case 0x93:
			print("Signed Static Application Data - (93): " + value.toString(HEX));
			break;
		case 0xBF0C:
			print("FCI Issuer Discretionary Data Tag BF0C: ");
			break;
		case 0x9F4D:
			print("Log Entry - (9F4D): " + value.toString(HEX));
			break;
		case 0x9F6E:
			print("Third Party Data - (9F6E): " + value.toString(HEX));
			break;
		case 0x70:
			print("Constructed Data Element Tag 70: ");
			break;
		case 0x57:
			print("Track2 Equivalent Data - (57): " + value.toString(HEX));
			break;
		case 0x5F20:
			print("Cardholder Name - (5F20): " + value.toString(HEX) + " - " + value.toString(ASCII));
			break;
		case 0x9F1F:
			print("Track1 Discretionary Data - (9F1F): " + value.toString(HEX));
			break;
		case 0x5A:
			print("PAN - (5A): " + value.toString(HEX));
			break;
		case 0x5F34:
			print("PAN Sequence Number - (5F34): " + value.toString(HEX));
			break;
		case 0x5F24:
			print("Application Expiration Date - (5F24): " + value.toString(HEX));
			break;
		case 0x9F07:
			print("Application Usage Control - (9F07): " + value.toString(HEX));
			break;
		case 0x5F28:
			print("Issuer Country Code - (5F28): " + value.toString(HEX));
			break;
		case 0x5F25:
			print("Application Effective Date - (5F25): " + value.toString(HEX));
			break;
		case 0x9F0E:
			print("IAC Denial - (9F0E): " + value.toString(HEX));
			break;
		case 0x9F0F:
			print("IAC Online - (9F0F): " + value.toString(HEX));
			break;
		case 0x9F0D:
			print("IAC Default - (9F0D): " + value.toString(HEX));
			break;
		case 0x5F30:
			print("Service Code - (5F30): " + value.toString(HEX));
			break;
		case 0x9F42:
			print("Application Currency Code - (9F42): " + value.toString(HEX));
			break;
		case 0x9F44:
			print("Application Currency Exponent - (9F44): " + value.toString(HEX));
			break;
		case 0x8C:
			print("CDOL1 - (8C): " + value.toString(HEX));
			break;
		case 0x8D:
			print("CDOL2 - (8D): " + value.toString(HEX));
			break;
		case 0x9F08:
			print("Application Version Number - (9F08): " + value.toString(HEX));
			break;
		case 0x8E:
			print("CVM List - (8E): " + value.toString(HEX));
			break;
		case 0x8F:
			print("Certification Authority Public Key Index - (8F): " + value.toString(HEX));
			break;
		case 0x90:
			print("Issuer Public Key Certificate - (90): " + value.toString(HEX));
			break;
		case 0x92:
			print("Issuer Public Key Remainder - (92): " + value.toString(HEX));
			break;
		case 0x9F32:
			print("Issuer Public Key Exponent - (9F32): " + value.toString(HEX));
			break;
		case 0x9F46:
			print("ICC Public Key Certificate - (9F46): " + value.toString(HEX));
			break;
		case 0x9F47:
			print("ICC Public Key Exponent - (9F47): " + value.toString(HEX));
			break;
		case 0x9F49:
			print("DDOL - (9F49): " + value.toString(HEX));
			break;	
		case 0x9F69:
			print("Contactless Card Authentication Related Data - (9F69): " + value.toString(HEX));
			break;
		case 0x9F4B:
			print("Signed Dynamic Application Data - (9F4B): " + value.toString(HEX));
			break;
		case 0x9F27:
			print("Cryptogram Information Data - (9F27): " + value.toString(HEX));
			break;
		case 0x9F36:
			print("ATC - (9F36): " + value.toString(HEX));
			break;
		case 0x9F26:
			print("Application Cryptogram - (9F26): " + value.toString(HEX));
			break;
		case 0x9F10:
			print("Issuer Application Data - (9F10): " + value.toString(HEX));
			break;
		case 0x9F17:
			print("PIN Try Counter - (9F17): " + value.toString(HEX));
			break;	
		case 0x4F:
			print("Application Identifier (AID) - 4F: " + value.toString(HEX));
			break;
		case 0x84:
			print("Application Identifier (AID) - 84: " + value.toString(HEX));
			break;
		case 0x88:
			print("SFI of PSE Dir File - 88: " + value.toString(HEX));
			break;
		case 0x50:
			print("Application Label - 50: " + value.toString(HEX) + " - " + value.toString(ASCII));
			break;
		case 0x5F2D:
			print("Language Preference - 5F2D: " + value.toString(ASCII));
			break;
		case 0x9F38: 
			print("Processing Options Data Object List (PDOL) - 9F38: " + value.toString(HEX));
			break;
		case 0x87:
			print("Application Priority Indicator - 87: " + value.toString(HEX));
			break;
		case 0x9F12:
			print("Application Preferred Name - 9F12: " + value.toString(ASCII));
			break;
		case 0x9F11:
			print("Issuer Code Table Index - 9F11: " + value.toString(HEX));
			break;
		case 0x82:
			print("Application Interchange Profile - AIP - 82: " + value.toString(HEX));
			break;
		case 0x94:
			print("Application File Locator - AFL - 94: " + value.toString(HEX));
			break;
		default:
			if(typeof(EMVView.DE[tag]) == "undefined"){
				print("Unknown Class: " + tag.toString(HEX));
					print()
				}
				else{
					print(EMVView.DE[tag] + value.toString(HEX));
					print();
				}
				break;				 
		}
}












/**
 * Try a list of predefined AID in order to select an application
 */
EMV.prototype.tryAID = function() {
	
	for (var i = 0; i < EMV.AIDLIST.length; i++) {
		var le = EMV.AIDLIST[i];
		var aid = new ByteString(le.aid, HEX);
		var fci = this.select(aid, true);
		
		
		if (fci.length > 0) {
			this.cardDE[EMV.AID] = aid;
			this.decodeFCI(fci);
			
		} 
	}
	
	return this.cardDE[EMV.AID]
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
			this.log("Found data element " + t.getTag().toString(16) + " = " + t.getValue().toString(HEX));
			this.cardDE[t.getTag()] = t.getValue();
		}
	}
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
	if(iccPublicKeyModulus != undefined){
	var p1 = 0x90;
	var iccPublicKeyModulus = iccPublicKeyModulus;
	var iccPublicKeyModulus2 = iccPublicKeyModulus.bytes(0,l);
	}else{
	var p1 = 0x80;
	}
		
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

	if (ValidatePin){
		print("======================================================================================");
		print("VERIFY PIN");
		print("======================================================================================");
		var tagD7 = card.sendApdu(0x80,0xCA,0x00,0xD7,0x00);
		print("<send> 80 CA 00 D7 00" );
		//print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
		//Does the card support offline plaintext verification?
		if((tagD7.byteAt(2)>>2)%2==0){
			print("Card does not support PIN verification\n");
			throw na
		}
		//If it supports plaintext PIN verification, the command is sent:
		var answer = card.sendApdu(0x00,0x20,0x00,0x80, new ByteString("24" + PARAMETERS.PIN + "FFFFFFFFFF", HEX),8);
		print("<send> 00 20 00 80 08 24 " +PARAMETERS.PIN.toString(HEX) + " FF FF FF FF FF");
		print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
		if(card.SW.toString(16) == "9000"){
			throw ok	
		}else{throw error}	
		
	}

	var tagD5 = card.sendApdu(0x80,0xCA,0x00,0xD7,0x00);
	//print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	//Does the card support offline plaintext verification?
	if((tagD5.byteAt(2)>>1)%2==1){
		testing_UnpredNumber=false;
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
	
	print("Constructed Data Element Tag 77");
	var GenAC = new ASN1(generateAC);
	var ac = GenAC;
			
	if (ac != null) {
		for (var i = 0; i < ac.elements; i++) {
			this.cardDE[ac.get(i).tag] = ac.get(i).value;
			tg=ac.get(i).tag;
			vl=ac.get(i).value;
			
			this.decodeDataElement(tg,vl);
		}
	}
	print("End of constructed Data Element Tag 77\n");
	
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
		if(SDADlength !== iccPublicKeyModulus2.length){
			print("ICC Public Key Modulo length is not equal to Signed Dynamic Application Data length");
			throw error
		}
		print("ICC Public Key Modulo length " + iccPublicKeyModulus2.length + " is equal to Signed Dynamic Application Data length " + SDADlength + "\n");
		// Step 2: The Recovered Data Trailer is equal to 'BC'
		if(decryptedSDAD.byteAt(decryptedSDAD.length - 1) !== 0xBC){
			print("The Recovered Data Trailer is not equal to 'BC'");
			throw error
		}
		print("The Recovered Data Trailer is equal to 'BC'");
		// Step 3: The Recovered Data Header is equal to '6A'
		if((decryptedSDAD.byteAt(0) !== 0x6A)){
			print("The Recovered Data Header is not equal to '6A'");
			throw error
		}
		print("The Recovered Data Header is equal to '6A'");
		// Step 4: The Signed Data Format is equal to '05'
		if(decryptedSDAD.byteAt(1) !== 0x05){
			print("Certificate Format is not equal to '05'");
			throw error
		}
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
	
	
		if(CryptoID.toString(HEX) !=  GenAC.get(0).value){
			print("Cryptogram Information Data in ICC Dynamic Data is not equal to the value retrieved in GENERATE AC response");
			throw error
		}  
		print("Cryptogram Information Data " + CryptoID.toString(HEX) + " in ICC Dynamic Data identical to the value retrieved in GENERATE AC response");
		
		var PP = SDADlength - iccDDlength - 0x19;
		var longi = iccDDlength + 4 + PP;
		var HashRecovered = decryptedSDAD.bytes(longi,0x14); //Recovered Hash
		
		var bufferSign = (decryptedSDAD.bytes(01,03 + iccDDlength + PP)).concat(unpredictableNumber);
		print("Buffer for Hash Verification (Signature): " + bufferSign.toString(HEX));
		
		
		var hashsign = this.crypto.digest(Crypto.SHA_1, bufferSign);
		print("Hash Result: " + hashsign.toString(HEX)); // Hash calculated. 
			
		if(hashsign.toString(HEX) !== HashRecovered.toString(HEX)){
			print("The calculated Hash result is not equal to the recovered Hash result");	
			throw error
		}																		  
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
		
		if(hashtrans.toString(HEX) !== TraDHash.toString(HEX)){
			print("The calculated Hash result is not equal to the recovered Hash result");
			throw error
		}  
		print("The calculated Hash result is equal to the recovered Hash result");
		print("Combined Dynamic Data Authentication verification - OK\n");
		if (CDAValidation){
			throw ok
		}	   
	}
	
	var valid	= this.CryptoValidation(generateAC);
	var MAC = valid[0];
	var ARPC = valid[1];
	var DKsmi = valid[2];
	var DKsmc = valid[3];
	
	if(p1 == 0x90){
		if(MAC.toString(HEX) == Cryptogram.toString(HEX)){
			print("Successful Cryptogram Verification ")
		}else{
			print("Unsuccessful Cryptogram Verification ")
		}
	}else{
		var cryptoauth = this.cardDE[0x9F26];
		if(MAC.toString(HEX) == cryptoauth.toString(HEX)){
			print("Successful Cryptogram Verification ")
			if (OnlineValidation){throw ok}
			
		}else{
			print("Unsuccessful Cryptogram Verification ")
			if (OnlineValidation){throw error}
		}	
	}
	
	return [MAC,ARPC,DKsmi,DKsmc];
	
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

		print("Constructed Data Element Tag 77");
		
		var GenAC = new ASN1(generateAC);
		var ac = GenAC;
				
		if (ac != null) {
			for (var i = 0; i < ac.elements; i++) {
				this.cardDE[ac.get(i).tag] = ac.get(i).value;
				tg=ac.get(i).tag;
				vl=ac.get(i).value;
				
				this.decodeDataElement(tg,vl);
			}
		}
		print("End of constructed Data Element Tag 77\n");
		
		var valid	= this.CryptoValidation(generateAC);
		var MAC = valid[0];
		
		var cryptoauth = this.cardDE[0x9F26];
		if(MAC.toString(HEX) == cryptoauth.toString(HEX)){
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
	var Keysmi = new ByteString(PARAMETERS.KEY_SMI,HEX);
	var keysmc = new ByteString(PARAMETERS.KEY_SMC,HEX);
	print("MKac= " + keyac.toString(HEX));
	print("MKsmi= " + Keysmi.toString(HEX));
	print("MKsmc= " + keysmc.toString(HEX));
	var PANumber = this.cardDE[0x5A];
	var PSN = this.cardDE[0x5F34];
	var unpredictableNumber = this.terminalDE[EMV.UN];
	
	
	//PAN|PSN
	
	var block = PANumber.concat(PSN);
	print("PAN|PSN : " + block.toString(HEX));
	var block2 = block.right(8);
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
	
	//Session Key generation 
	
	var GAC = new ASN1(generateAC);
	var ATC = GAC.get(1).value.toString(HEX);

	
	
	
	if(testing_UnpredNumber){
		var b1 = ATC.concat("F000");
		var b2 = new ByteString(b1.concat(unpredictableNumber),HEX);
	
		var b3 = ATC.concat("0F00");
		var b4 = new ByteString(b3.concat(unpredictableNumber),HEX);
	} else {
		var b1 = ATC.concat("F000");
		var b2 = new ByteString(b1.concat("00000000"),HEX);
	
		var b3 = ATC.concat("0F00");
		var b4 = new ByteString(b3.concat("00000000"),HEX);
	}
	
	
	//var chiper2 = new ByteString(b2.concat(b4),HEX);
	
	print("Input Data Block A: " + b2.toString(HEX));
	print("Input Data Block B: " + b4.toString(HEX));
	
	var DKac2 = new Key();
	DKac2.setComponent(Key.DES,DKac);
	
	var sKacl = crypto.encrypt(DKac2,Crypto.DES_ECB,b2);
	var sKacr = crypto.encrypt(DKac2,Crypto.DES_ECB,b4);
	
	var sKac = sKacl.concat(sKacr);
	
	print("SKac = 3DES_ECB(DKac)[Input Data Block A|Input Data Block B] = " + sKac.toString(HEX) + "\n")
	
	//Session Key
	var sKac2 = new Key();
	sKac2.setComponent(Key.DES,sKac);
	
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
	var ATC1 = GAC.get(1).value
	var iad = GAC.get(3).value;
	var CVR = iad.bytes(2,6);
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
	var DE11 = DE10.toString(HEX).concat("80");

	var skac2DES = new Key();
	skac2DES.setComponent(Key.DES,sKac.bytes(0,8));
	
	var DE12 = new ByteString(DE11,HEX);
	
	print("Input Data to Cryptogram = " + DE12.toString(HEX) + "\n"); 
	
	var B1 = new ByteString("0000000000000000",HEX);
	
	for(var x=0;x<DE12.length;x+=8){
		var B2 = DE12.bytes(x,8);
		var B3 = B1.xor(B2);
	
		print("B1[" + B1.toString(HEX) + "] " + "XOR " + "B2[" + B2.toString(HEX) + "] " + "=" + "B3[" + B3.toString(HEX) + "]");
	
		B1 = crypto.encrypt(skac2DES,Crypto.DES_ECB,B3);
		
		if(x<(DE12.length - 8)){
			print("DES([" + sKac.bytes(0,8).toString(HEX) + "], B3[" + B3.toString(HEX) + "]) = [" + B1.toString(HEX) + "] = Next B1" );
		}
	}

	var MAC = crypto.encrypt(sKac2,Crypto.DES_ECB,B3); //Cryptogram value calculated 
	print("MAC Cryptogram = " + MAC.toString(HEX));

	var ARPCResCod = this.issuerDE[0x1F68].toString(HEX);
	var t1 = new ByteString(ARPCResCod.concat("000000000000"),HEX);
	var t2 = new ByteString(MAC,HEX);
	
	var ARPCResCod2 = t2.xor(t1);
	var ARPC = crypto.encrypt(skac2DES,Crypto.DES_ECB,ARPCResCod2);
		
	return [MAC,ARPC,DKsmi,DKsmc];
	
}

EMV.prototype.Appblock = function(mac,DKsmi,DKsmc){

	print("======================================================================================");
	print("APPLICATION BLOCK");
	print("======================================================================================");

	var Session = this.SessionIntegrity(mac,DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var dataMAC = new ByteString("841E000008",HEX);
	var ATC = new ByteString(this.cardDE[0x9F36],HEX);
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
	
	if(card.SW.toString(16) == "9000"){
	throw ok	
	}else{throw error}
	
	return newmac;
}


EMV.prototype.AppUnblock = function(mac,DKsmi,DKsmc){

	print("======================================================================================");
	print("APPLICATION UNBLOCK");
	print("======================================================================================");

	var Session = this.SessionIntegrity(mac,DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var dataMAC = new ByteString("8418000008",HEX);
	var ATC = new ByteString(this.cardDE[0x9F36],HEX);
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
	
	if(card.SW.toString(16) == "9000"){
	throw ok	
	}else{throw error}
	
	return newmac;
}


EMV.prototype.PinUnblock = function(mac,DKsmi,DKsmc){

	print("======================================================================================");
	print("PIN UNBLOCK");
	print("======================================================================================");

	var Session = this.SessionIntegrity(mac,DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var dataMAC = new ByteString("8424000008",HEX);
	var ATC = new ByteString(this.cardDE[0x9F36],HEX);
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
	
	if(card.SW.toString(16) == "9000"){
	throw ok	
	}else{throw error}	
	
	return newmac;


}


EMV.prototype.PinChange = function(mac,DKsmi,DKsmc){
	print("======================================================================================");
	print("PIN CHANGE");
	print("======================================================================================");

	var Session = this.SessionIntegrity(mac,DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	var sKsmc = Session[2];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	var sKsmc2 = new Key();
	sKsmc2.setComponent(Key.DES,sKsmc);
	
	print("SKsmc = 3DES_ECB(DKsmc)[Input Data Block A|Input Data Block B] = " + sKsmc.toString(HEX) + "\n");
	
	var PIN = new ByteString(PARAMETERS.PIN,HEX);
	var PINblock = new ByteString("24" + PIN + "FFFFFFFFFF",HEX);
	
	print("PIN=" + PIN.toString(HEX));
	print("PIN Block=" + PINblock.toString(HEX));
	
	var EncrypPIN = crypto.encrypt(sKsmc2,Crypto.DES_ECB,PINblock);
	print("Encrypted PIN Block=3DES_ECB(SKsmc)[PIN Block]=" + EncrypPIN.toString(HEX));
	
	
	
	var dataMAC = new ByteString("8424000210",HEX);
	var ATC = new ByteString(this.cardDE[0x9F36],HEX);
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
	
	print("<send> 84 24 00 02 10 " + Datacommand);
	
	print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	
	
	if(card.SW.toString(16) == "9000"){
	throw ok	
	}else{throw error}	
	return
	
	return newmac;
	
	
	
}


EMV.prototype.PutData = function(mac,DKsmi,DKsmc){

	print("======================================================================================");
	print("PUT DATA");
	print("======================================================================================");

	var Session = this.SessionIntegrity(mac,DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	print("CLA|INS|P1|P2=84DA" + PARAMETERS.PUTDATA_TAGG);
	
	var number = (PARAMETERS.PUTDATA_VALUE.length)/2 + 8;
	
	
	if(number>15){
		var data3=number.toString(HEX);
	} else {
		var data3="0" + number.toString(HEX);
	}
	var dataMAC = new ByteString("84DA",HEX) + new ByteString(PARAMETERS.PUTDATA_TAGG, HEX) + new ByteString(data3,HEX);
	var ATC = new ByteString(this.cardDE[0x9F36],HEX);
	var MAC = new ByteString(mac,HEX);
	
	var data = dataMAC.concat(ATC).concat(MAC).concat(PARAMETERS.PUTDATA_VALUE) + "80";
	
	if(data%12!=0){
		var counter=data%12;
		var i=0;
		var zeros="00";
		for(i=1;i<counter; i++){
			zeros=zeros+"00";
		}
	}
	
	data=data+zeros;
	
	var data2 = new ByteString(data,HEX);
	print("Input Data to MAC=" + data2.toString(HEX));
	
	var dataMAC = crypto.sign(sKsmi2, Crypto.DES_MAC_EMV,data2);
	
	print("MAC(SKsmi)[MAC Input Data]=" + dataMAC.toString(HEX));
	
	var P1=PARAMETERS.PUTDATA_TAGG.charAt(0).toString() + PARAMETERS.PUTDATA_TAGG.charAt(1).toString();
	var P2=PARAMETERS.PUTDATA_TAGG.charAt(2).toString() + PARAMETERS.PUTDATA_TAGG.charAt(3).toString();
	
	
	var test= new ByteString(PARAMETERS.PUTDATA_VALUE,HEX);
	var putcommand=test.concat(dataMAC);
	var cardputdata = card.sendApdu(0x84, 0xDA, parseInt(P1,16), parseInt(P2,16), putcommand);	
	
	print("Increment ARQC by 1 = " + newmac.toString(HEX));
	
	print("<send> 84 DA " + P1 +" "+ P2 + " "+ data3 +" " + putcommand);
	
	print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	
	if(card.SW.toString(16) == "9000"){
	throw ok	
	}else{throw error}	
	
	return newmac;
}



EMV.prototype.UpdateRecord = function(mac,DKsmi,DKsmc){

	print("======================================================================================");
	print("UPDATE RECORD");
	print("======================================================================================");

	var Session = this.SessionIntegrity(mac,DKsmi,DKsmc);
	var sKsmi = Session[0];
	var newmac = Session[1];
	
	//Session Key
	var sKsmi2 = new Key();
	sKsmi2.setComponent(Key.DES,sKsmi);
	
	print("CLA|INS|P1|P2=84DC" + PARAMETERS.UPREC_TAG);
	
	var number = (PARAMETERS.UPREC_VALUE.length)/2 + 8;
	
	
	if(number>15){
		var data3=number.toString(HEX);
	} else {
		var data3="0" + number.toString(HEX);
	}
	var dataMAC = new ByteString("84DC",HEX) + new ByteString(PARAMETERS.UPREC_TAG, HEX) + new ByteString(data3,HEX);
	var ATC = new ByteString(this.cardDE[0x9F36],HEX);
	var MAC = new ByteString(mac,HEX);
	
	var data = dataMAC.concat(ATC).concat(MAC).concat(PARAMETERS.UPREC_VALUE) + "80";
	
	if(data%12!=0){
		var counter=data%12;
		var i=0;
		var zeros="00";
		for(i=1;i<counter; i++){
			zeros=zeros+"00";
		}
	}
	
	data=data+zeros;
	
	var data2 = new ByteString(data,HEX);
	print("Input Data to MAC=" + data2.toString(HEX));
	
	var dataMAC = crypto.sign(sKsmi2, Crypto.DES_MAC_EMV,data2);
	
	print("MAC(SKsmi)[MAC Input Data]=" + dataMAC.toString(HEX));
	
	var P1=PARAMETERS.UPREC_TAG.charAt(0).toString() + PARAMETERS.UPREC_TAG.charAt(1).toString();
	var P2=PARAMETERS.UPREC_TAG.charAt(2).toString() + PARAMETERS.UPREC_TAG.charAt(3).toString();
	
	
	var test= new ByteString(PARAMETERS.UPREC_VALUE,HEX);
	var putcommand=test.concat(dataMAC);
	var cardputdata = card.sendApdu(0x84, 0xDC, parseInt(P1,16), parseInt(P2,16), putcommand);	
	
	print("Increment ARQC by 1 = " + newmac.toString(HEX));
	
	print("<send> 84 DC " + P1 +" "+ P2 + " "+ data3 +" " + putcommand);
	
	print("<rcv> " + "SW1/SW2=" + card.SW.toString(16));
	
	if(card.SW.toString(16) == "9000"){
	throw ok	
	}else{throw error}	
	
	return newmac;
}


EMV.prototype.SessionIntegrity = function(mac,DKsmi,DKsmc){
	
	var macleft = new ByteString(mac.left(2),HEX);
	var macright = new ByteString(mac.right(5),HEX);
	var maccent1 = new ByteString("F0",HEX);
	var maccent2 = new ByteString("0F",HEX);
	var blockA = macleft.concat(maccent1).concat(macright);
	var blockB = macleft.concat(maccent2).concat(macright);
	print("Input Data Block A to SKsmi=" + blockA.toString(HEX));
	print("Input Data Block A to SKsmi=" + blockB.toString(HEX));
	
	var DKsmi2 = new Key();
	DKsmi2.setComponent(Key.DES,DKsmi);
	
	var sKsmil = crypto.encrypt(DKsmi2,Crypto.DES_ECB,blockA);
	var sKsmir = crypto.encrypt(DKsmi2,Crypto.DES_ECB,blockB);
	
	var sKsmi = sKsmil.concat(sKsmir);
	
	print("SKsmi = 3DES_ECB(DKsmi)[Input Data Block A|Input Data Block B] = " + sKsmi.toString(HEX) + "\n")
	
	var DKsmc2 = new Key();
	DKsmc2.setComponent(Key.DES,DKsmc);
	
	var sKsmcl = crypto.encrypt(DKsmc2,Crypto.DES_ECB,blockA);
	var sKsmcr = crypto.encrypt(DKsmc2,Crypto.DES_ECB,blockB);
	
	var sKsmc = sKsmcl.concat(sKsmcr);
	
	//var newmac = new ByteString(mac,HEX);
	var newmac = mac.add(1);
	
	return [sKsmi,newmac,sKsmc];
}



EMV.prototype.CDOL = function(tag1,l1){
	switch (tag1) {
		case "91":
			var firstGAC = arpc.concat(this.issuerDE[0x1F68]);
			return firstGAC.toString(HEX);
			break;
		case "8A":
			var TransDate = this.issuerDE[0x8A];
			return TransDate.toString(HEX);
			break;
		case "9A":
			var TransDate = new ByteString("000000",HEX);
			return TransDate.toString(HEX);
			break;
		case "9C":
			var TransType = new ByteString("00",HEX);
			return TransType.toString(HEX);
			break;
		case "95":
			var TVR = new ByteString("0000000000",HEX);
			return TVR.toString(HEX);
			break;
		case "9F02":
			var amount = new ByteString("000000005000",HEX);
			return amount.toString(HEX);
			break;
		case "9F03":
			var amountother = new ByteString("000000000000",HEX);
			return amountother.toString(HEX);
			break;
		case "9F1A":
			var TermCC = new ByteString("0152",HEX);
			return TermCC.toString(HEX);
			break;
		case "5F2A":
			var TransCC = new ByteString("0152",HEX);
			return TransCC.toString(HEX);
			break;
		case "9F37":
			var unpredictableNumber1 = this.terminalDE[EMV.UN];
			return unpredictableNumber1.toString(HEX);
			break;
		case "9F35":
			var terminaltype = new ByteString("22", HEX);
			return terminaltype.toString(HEX);
			break;
		case "9F45":
			var DataAuthCode = new ByteString("0000", HEX);
			return DataAuthCode.toString(HEX);
			break;
		case "9F4C":
			var iccDynamicNumber2 = iccDynamicNumber;
			return iccDynamicNumber2.toString(HEX);
			break;
		case "9F34":
			var CVMResults = new ByteString("000000", HEX);
			return CVMResults.toString(HEX);
			break;
		default:
			var Tag2 = "00";
			var x = 1;
			while(x < parseInt(l1,16)){
			Tag2 += "00";
			x++
			} 
			return(Tag2)
			break;				 
		}
}
