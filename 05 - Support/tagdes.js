function tagdes(){
}

tagdes.prototype.decodeDE = function(tag,value){

	switch (tag) {
		case 0x42:
			print("Issuer Identification Number - IIN - 42: " + value.toString(HEX));
			break;
		case 0x4F:
			print("Application Identifier (AID) - 4F: " + value.toString(HEX));
			break;
		case 0x50:
			print("Application Label - 50: " + value.toString(HEX) + " - " + value.toString(ASCII));
			break;
		case 0x57:
			print("Track2 Equivalent Data - 57: " + value.toString(HEX));
			break;
		case 0x5A:
			print("PAN - 5A: " + value.toString(HEX));
			break;
		case 0x5F55:
			print("Issuer Country Code (Alpha 2 Format) - 5F55: " + value.toString(HEX));
			break;	
		case 0x82:
			print("Application Interchange Profile - AIP - 82: " + value.toString(HEX));
			break;
		case 0x84:
			print("Application Identifier (AID) - 84: " + value.toString(HEX));
			break;
		case 0x87:
			print("Application Priority Indicator - 87: " + value.toString(HEX));
			break;
		case 0x88:
			print("SFI of PSE Dir File - 88: " + value.toString(HEX));
			break;
		case 0x8A:
			print("Authorization Response Code - 8A: " + value.toString(HEX));
			break;
		case 0x8C:
			print("CDOL1 - 8C: " + value.toString(HEX));
			break;
		case 0x8D:
			print("CDOL2 - 8D: " + value.toString(HEX));
			break;
		case 0x8E:
			print("CVM List - 8E: " + value.toString(HEX));
			break;
		case 0x8F:
			print("Certification Authority Public Key Index - 8F: " + value.toString(HEX));
			break;
		case 0x90:
			print("Issuer Public Key Certificate - 90: " + value.toString(HEX));
			break;
		case 0x92:
			print("Issuer Public Key Remainder - 92: " + value.toString(HEX));
			break;
		case 0x93:
			print("Signed Static Application Data - 93: " + value.toString(HEX));
			break;
		case 0x94:
			print("Application File Locator - AFL - 94: " + value.toString(HEX));
			break;
		case 0x5F20:
			print("Cardholder Name - 5F20: " + value.toString(HEX) + " - " + value.toString(ASCII));
			break;
		case 0x5F24:
			print("Application Expiration Date - 5F24: " + value.toString(HEX));
			break;
		case 0x5F25:
			print("Application Effective Date - 5F25: " + value.toString(HEX));
			break;
		case 0x5F28:
			print("Issuer Country Code - 5F28: " + value.toString(HEX));
			break;
		case 0x5F2D:
			print("Language Preference - 5F2D: " + value.toString(ASCII));
			break;
		case 0x5F30:
			print("Service Code - 5F30: " + value.toString(HEX));
			break;
		case 0x5F34:
			print("PAN Sequence Number - 5F34: " + value.toString(HEX));
			break;
		case 0x5F56:
			print("Issuer Country Code - 5F56: " + value.toString(HEX));
			break;
		case 0x9F07:
			print("Application Usage Control - 9F07: " + value.toString(HEX));
			break;
		case 0x9F08:
			print("Application Version Number - 9F08: " + value.toString(HEX));
			break;
		case 0x9F10:
			print("Issuer Application Data - 9F10: " + value.toString(HEX));
			break;
		case 0x9F0B:
			print("Cardholder Name Extended - 9F0B: " + value.toString(HEX));
			break;
		case 0x9F0D:
			print("IAC Default - 9F0D: " + value.toString(HEX));
			break;
		case 0x9F0E:
			print("IAC Denial - 9F0E: " + value.toString(HEX));
			break;
		case 0x9F0F:
			print("IAC Online - 9F0F: " + value.toString(HEX));
			break;
		case 0x9F11:
			print("Issuer Code Table Index - 9F11: " + value.toString(HEX));
			break;
		case 0x9F12:
			print("Application Preferred Name - 9F12: " + value.toString(ASCII));
			break;
		case 0x9F13:
			print("Last Online ATC Register - 9F13: " + value.toString(HEX));
			break;
		case 0x9F14:
			print("Lower Consecutive Offline Limit - 9F14: " + value.toString(HEX));
			break;
		case 0x9F17:
			print("PIN Try Counter - 9F17: " + value.toString(HEX));
			break;
		case 0x9F1F:
			print("Track1 Discretionary Data - 9F1F: " + value.toString(HEX));
			break;
		case 0x9F20:
			print("Track 2 Discretionary Data - 9F20: " + value.toString(HEX));
			break;
		case 0x9F23:
			print("Upper Consecutive Offline Limit - 9F23: " + value.toString(HEX));
			break;
		case 0x9F26:
			print("Application Cryptogram - 9F26: " + value.toString(HEX));
			break;
		case 0x9F27:
			print("Cryptogram Information Data - 9F27: " + value.toString(HEX));
			break;
		case 0x9F2A:
			print("Kernel Identifier - 9F2A: " + value.toString(HEX));
			break;
		case 0x9F2D:
			print("ICC PIN Encipherment Public Key Certificate - 9F2D: " + value.toString(HEX));
			break;
		case 0x9F2E:
			print("ICC PIN Encipherment Public Key Exponent - 9F2E: " + value.toString(HEX));
			break;
		case 0x9F2F:
			print("ICC PIN Encipherment Public Key Remainder - 9F2F: " + value.toString(HEX));
			break;
		case 0x9F32:
			print("Issuer Public Key Exponent - 9F32: " + value.toString(HEX));
			break;
		case 0x9F34:
			print("CVM Results - 9F34: " + value.toString(HEX));
			break;
		case 0x9F36:
			print("ATC - 9F36: " + value.toString(HEX));
			break;
		case 0x9F38: 
			print("Processing Options Data Object List (PDOL) - 9F38: " + value.toString(HEX));
			break;
		case 0x9F42:
			print("Application Currency Code - 9F42: " + value.toString(HEX));
			break;
		case 0x9F44:
			print("Application Currency Exponent - 9F44: " + value.toString(HEX));
			break;
		case 0x9F46:
			print("ICC Public Key Certificate - 9F46: " + value.toString(HEX));
			break;
		case 0x9F47:
			print("ICC Public Key Exponent - 9F47: " + value.toString(HEX));
			break;
		case 0x9F48:
			print("ICC Public Key Remainder - 9F48: " + value.toString(HEX));
			break;
		case 0x9F49:
			print("DDOL - 9F49: " + value.toString(HEX));
			break;	
		case 0x9F4A:
			print("Static Data Authentication Tag List - 9F4A: " + value.toString(HEX));
			break;
		case 0x9F4B:
			print("Signed Dynamic Application Data - 9F4B: " + value.toString(HEX));
			break;
		case 0x9F4D:
			print("Log Entry - 9F4D: " + value.toString(HEX));
			break;
		case 0x9F4F:
			print("Log Format - 9F4F: " + value.toString(HEX));
			break;	
		case 0x9F6A:
			print("Unpredictable Number (Numeric) - 9F6A: " + value.toString(HEX));
			break;
		case 0xDF62:
			print("Application Selection Flag - DF62: " + value.toString(HEX));
			break;	
		//[MASTERCARD]
		case 0x56:
			print("Track 1 Data - 56: " + value.toString(HEX));
			break;
		case 0x9F4C:
			print("ICC Dynamic Number - 9F4C: " + value.toString(HEX));
			break;
		case 0x9F50:
			print("Offline Accumulator Balance 1 - 9F50: " + value.toString(HEX));
			break;
		case 0x9F51:
			print("DRDOL - 9F51: " + value.toString(HEX));
			break;
		case 0x9F58:
			print("Offline Accumulator Balance 2 - 9F58: " + value.toString(HEX));
			break;
		case 0x9F59:
			print("Offline Counter Balance 2 - 9F59: " + value.toString(HEX));
			break;
		case 0x9F5B:
			print("DSDOL - 9F5B: " + value.toString(HEX));
			break;
		case 0x9F60:
			print("CVC3 Track 1 - 9F60: " + value.toString(HEX));
			break;
		case 0x9F61:
			print("CVC3 Track 2 - 9F61: " + value.toString(HEX));
			break;
		case 0x9F62:
			print("Track 1 Bit Map for CVC3 (PCVC3_track1) - 9F62: " + value.toString(HEX));
			break;
		case 0x9F63:
			print("Track 1 Bit Map for UN and ATC (PUNATC_track1) - 9F63: " + value.toString(HEX));
			break;
		case 0x9F64:
			print("Track 1 Number of ATC Digits (NATC_track1) - 9F64: " + value.toString(HEX));
			break;
		case 0x9F65:
			print("Track 2 Bit Map for CVC3 (PCVC3_track2) - 9F65: " + value.toString(HEX));
			break;
		case 0x9F66:
			print("Track 2 Bit Map for UN and ATC (PUNATC_track2) - 9F66: " + value.toString(HEX));
			break;
		case 0x9F67:
			print("Track 2 Number of ATC Digits (NATC_track2) - 9F67: " + value.toString(HEX));
			break;
		case 0x9F68:
			print("Mag Stripe CVM List - 9F68: " + value.toString(HEX));
			break;
		case 0x9F6B:
			print("Track 2 Data - 9F6B: " + value.toString(HEX));
			break;
		case 0x9F6C:
			print("MagStripe Application Version Number - 9F6C: " + value.toString(HEX));
			break;
		case 0x9F7A:
			print("Offline Counter Balance 1 - 9F7A: " + value.toString(HEX));
			break;
		case 0x9F7C:
			print("Merchant Custom Data - 9F7C: " + value.toString(HEX));
			break;
		case 0x9F7E:
			print("Application Life Cycle Data - 9F7E: " + value.toString(HEX));
			break;
		case 0xC3:
			print("Card Issuer Action Code - Decline - C3: " + value.toString(HEX));
			break;
		case 0xC4:
			print("Card Issuer Action Code - Default - C4: " + value.toString(HEX));
			break;
		case 0xC5:
			print("Card Issuer Action Code - Online - C5: " + value.toString(HEX));
			break;
		case 0xC6:
			print("PIN Try Limit - C6: " + value.toString(HEX));
			break;
		case 0xC7:
			print("CDOL 1 Related Data Length - C7: " + value.toString(HEX));
			break;
		case 0xC8:
			print("CRM Country Code - C8: " + value.toString(HEX));
			break;
		case 0xC9:
			print("Accumulator 1/CRM Currency Code - C9: " + value.toString(HEX));
			break;
		case 0xCA:
			print("Accumulator 1 Lower Limit (LCOTA) - CA: " + value.toString(HEX));
			break;
		case 0xCB:
			print("Accumulator 1 Upper Limit (UCOTA) - CB: " + value.toString(HEX));
			break;
		case 0xCD:
			print("Card Issuer Action Code (CL) - Default - CD: " + value.toString(HEX));
			break;
		case 0xCE:
			print("Card Issuer Action Code (CL) - Online - CE: " + value.toString(HEX));
			break;
		case 0xCF:
			print("Card Issuer Action Code (CL) - Decline - CF: " + value.toString(HEX));
			break;
		
		case 0xD1:
			print("Accumulator 1/CRM Currency Conversion Table - D1: " + value.toString(HEX));
			break;
		case 0xD3:
			print("Additional Check Table - D3: " + value.toString(HEX));
			break;
		case 0xD5:
			print("Application Control - D5: " + value.toString(HEX));
			break;
		case 0xD6:
			print("Default ARPC Response Code - D6: " + value.toString(HEX));
			break;
		case 0xD7:
			print("Application Control (CL) - D7: " + value.toString(HEX));
			break;
		case 0xDE:
			print("Log Data Table - DE: " + value.toString(HEX));
			break;
		case 0xDF11:
			print("Accumulator 1 Control - DF11: " + value.toString(HEX));
			break;
		case 0xDF12:
			print("Accumulator 1 Control (CL) - DF12: " + value.toString(HEX));
			break;
		case 0xDF13:
			print("Accumulator 2 Amount - DF13: " + value.toString(HEX));
			break;
		case 0xDF14:
			print("Accumulator 2 Control - DF14: " + value.toString(HEX));
			break;
		case 0xDF15:
			print("Accumulator 2 Control (CL) - DF15: " + value.toString(HEX));
			break;
		case 0xDF16:
			print("Accumulator 2 Currency Code - DF16: " + value.toString(HEX));
			break;
		case 0xDF17:
			print("Accumulator 2 Currency Conversion Table - DF17: " + value.toString(HEX));
			break;
		case 0xDF18:
			print("Accumulator 2 Lower Limit - DF18: " + value.toString(HEX));
			break;
		case 0xDF19:
			print("Accumulator 2 Upper Limit - DF19: " + value.toString(HEX));
			break;
		case 0xDF1A:
			print("Counter 1 Control - DF1A: " + value.toString(HEX));
			break;
		case 0xDF1B:
			print("Counter 1 Control (CL) - DF1B: " + value.toString(HEX));
			break;
		case 0xDF1C:
			print("Counter 1 Number - DF1C: " + value.toString(HEX));
			break;
		case 0xDF1D:
			print("Counter 2 Control - DF1D: " + value.toString(HEX));
			break;
		case 0xDF1E:
			print("Counter 2 Control (CL) - DF1E: " + value.toString(HEX));
			break;
		case 0xDF1F:
			print("Counter 2 Lower Limit - DF1F: " + value.toString(HEX));
			break;
		case 0xDF20:
			print("Counter 2 Number - DF20: " + value.toString(HEX));
			break;
		case 0xDF21:
			print("Counter 2 Upper Limit - DF21: " + value.toString(HEX));
			break;
		case 0xDF22:
			print("MTA CVM - DF22: " + value.toString(HEX));
			break;
		case 0xDF23:
			print("MTA CVM (CL) - DF23: " + value.toString(HEX));
			break;
		case 0xDF24:
			print("MTA Currency Code - DF24: " + value.toString(HEX));
			break;
		case 0xDF25:
			print("MTA No CVM - DF25: " + value.toString(HEX));
			break;
		case 0xDF26:
			print("MTA No CVM (CL) - DF26: " + value.toString(HEX));
			break;
		case 0xDF27:
			print("Number of Days Offline Limit - DF27: " + value.toString(HEX));
			break;
		case 0xDF28:
			print("Accumulator 1 CVR Dependancy Data - DF28: " + value.toString(HEX));
			break;
		case 0xDF29:
			print("Accumulator 1 CVR Dependancy Data (CL) - DF29: " + value.toString(HEX));
			break;
		case 0xDF2A:
			print("Accumulator 2 CVR Dependancy Data - DF2A: " + value.toString(HEX));
			break;
		case 0xDF2B:
			print("Accumulator 2 CVR Dependancy Data (CL) - DF2B: " + value.toString(HEX));
			break;
		case 0xDF2C:
			print("Counter 1 CVR Dependancy Data - DF2C: " + value.toString(HEX));
			break;
		case 0xDF2D:
			print("Counter 1 CVR Dependancy Data (CL) - DF2D: " + value.toString(HEX));
			break;
		case 0xDF2E:
			print("Counter 2 CVR Dependancy Data- DF2E: " + value.toString(HEX));
			break;
		case 0xDF2F:
			print("Counter 2 CVR Dependancy Data (CL) - DF2F: " + value.toString(HEX));
			break;
		case 0xDF30:
			print("Interface Enabling Switch - DF30: " + value.toString(HEX));
			break;
		case 0xDF3B:
			print("Accumulator 1 Amount - DF3B: " + value.toString(HEX));
			break;
		case 0xDF3C:
			print("CVR Issuer Discretionary Data - DF3C: " + value.toString(HEX));
			break;
		case 0xDF3D:
			print("CVR Issuer Discretionary Data (CL) - DF1B: " + value.toString(HEX));
			break;
		case 0xDF3E:
			print("Interface Identifier - DF3E: " + value.toString(HEX));
			break;
		case 0xDF3F:
			print("Read Record Filter - DF3F: " + value.toString(HEX));
			break;
		case 0xDF40:
			print("Read Record Filter (CL) - DF40: " + value.toString(HEX));
			break;
		
		case 0xBF0C:
			print("FCI Issuer Discretionary Data Tag BF0C: ");
			break;
		case 0x9F6E:
			print("Third Party Data - 9F6E: " + value.toString(HEX));
			break;
		case 0x70:
			print("Constructed Data Element Tag 70: ");
			break;
		case 0x9F69:
			print("Contactless Card Authentication Related Data - 9F69: " + value.toString(HEX));
			break;
		
		case 0x9F5D:
			print("Available Offline Spending Amount - 9F5D: " + value.toString(HEX));
			break;
		case 0xA5:
			print("FCI Proprietary Template Tag A5: " + value.toString(HEX));
			break;
		case 0x61:
			print("Application Template Tag 61: " + value.toString(HEX));
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