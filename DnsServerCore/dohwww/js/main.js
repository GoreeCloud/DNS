/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

$(function () {
    var link = "https://" + window.location.hostname + "/dns-query";

    var lnkDoH = $("#lnkDoH");

    lnkDoH.text(link);
    lnkDoH.attr("href", link);

    $("#btnCopyDoH").on("click", function () {
        var status = $("#copyDoHStatus");
        if (!window.isSecureContext || !navigator.clipboard || !navigator.clipboard.writeText) {
            status.text("Automatic copying is unavailable. Select and copy the URL above.");
            return;
        }
        navigator.clipboard.writeText(link).then(function () {
            status.text("Encrypted DNS URL copied.");
        }, function () {
            status.text("Could not copy automatically. Select and copy the URL above.");
        });
    });
});