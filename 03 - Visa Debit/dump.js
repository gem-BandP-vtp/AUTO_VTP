/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2013 CardContact Software & System Consulting
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
 * @fileoverview Example script for dumping the content of a credit card in human readable form
 */


load("emv.js");
load("emvView.js");

// Example code
var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

var crypto = new Crypto();

var e = new EMV(card, crypto);
var v = new EMVView(e);

e.selectPSE(false);

var aid = e.getAID();

if (aid != null) {
	e.selectADF(aid);
} else {
	e.tryAID();
}


e.initApplProc();
e.readApplData();

v.displayDataElements();

card.close();
