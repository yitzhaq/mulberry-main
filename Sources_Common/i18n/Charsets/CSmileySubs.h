/*
    Copyright (c) 2026 Mulberry contributors. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0
*/

// CSmileySubs.h — text equivalents for common emoji and symbols
//
// Overrides the CLDR short names with more concise or natural
// text representations. Three categories of entries:
//
//   1. Emoticons (:) ;) :P etc.) — based on Western emoticon
//      conventions documented at the sources below
//   2. Symbolic shorthand (<3 -> \o/ etc.) — common conventions
//   3. Short names ([coffee] [party] etc.) — hand-curated concise
//      alternatives to verbose CLDR names
//
// Sorted by codepoint for binary search. Pure ASCII only.
// Displayed wrapped in square brackets: [:)]
//
// TODO: hover/tooltip to show CLDR name and Unicode codepoint.
//
// References:
//   <https://en.wikipedia.org/wiki/List_of_emoticons>
//   <https://demos.joypixels.com/latest/ascii-smileys.html>
//   <https://unicode.org/emoji/charts/emoji-list.html>

#ifndef __CSMILEYSUBS__MULBERRY__
#define __CSMILEYSUBS__MULBERRY__

#include <stdint.h>
#include <stddef.h>


struct SSmileySub
{
	uint32_t	codepoint;
	const char*	text;
};

static const SSmileySub cSmileySubs[] = {
	{ 0x00A2, "\xA2" },          // cent sign
	{ 0x00A3, "\xA3" },          // pound sign
	{ 0x00A5, "\xA5" },          // yen sign
	{ 0x058F, "AMD" },           // Armenian dram
	{ 0x20A3, "FRF" },           // French franc
	{ 0x20A6, "NGN" },           // Nigerian naira
	{ 0x20A8, "Rs" },            // rupee sign
	{ 0x20A9, "KRW" },           // won sign
	{ 0x20AA, "ILS" },           // Israeli new sheqel
	{ 0x20AB, "VND" },           // Vietnamese dong
	{ 0x20AC, "EUR" },           // euro sign
	{ 0x20B9, "Rs" },            // Indian rupee
	{ 0x20BD, "RUB" },           // Russian ruble
	{ 0x20BF, "BTC" },           // bitcoin
	{ 0x203C, "!!" },            // double exclamation mark
	{ 0x2049, "!?" },            // exclamation question mark
	{ 0x2190, "<-" },            // leftwards arrow
	{ 0x2191, "^" },             // upwards arrow
	{ 0x2192, "->" },            // rightwards arrow
	{ 0x2193, "v" },             // downwards arrow
	{ 0x2194, "<->" },           // left right arrow
	{ 0x21A9, "<-'" },           // leftwards arrow with hook
	{ 0x21AA, "'->" },           // rightwards arrow with hook
	{ 0x2318, "cmd" },           // place of interest (command key)
	{ 0x2328, "kbd" },           // keyboard
	{ 0x23F0, "alarm" },         // alarm clock
	{ 0x23F3, "hourglass" },     // hourglass flowing sand
	{ 0x260E, "phone" },         // telephone
	{ 0x2611, "/" },             // check box with check
	{ 0x2615, "coffee" },        // hot beverage
	{ 0x2639, ":(" },            // frowning face
	{ 0x263A, ":)" },            // smiling face
	{ 0x2660, "spade" },         // spade suit
	{ 0x2663, "club" },          // club suit
	{ 0x2665, "<3" },            // black heart suit
	{ 0x2666, "diamond" },       // diamond suit
	{ 0x266A, "~*" },            // eighth note
	{ 0x267B, "recycle" },       // recycling symbol
	{ 0x26A0, "/!\\\\\\\\" },    // warning sign
	{ 0x26A1, "zap" },           // high voltage
	{ 0x26BD, "soccer" },        // soccer ball
	{ 0x26C4, "snowman" },       // snowman without snow
	{ 0x2705, "/" },             // check mark button
	{ 0x2708, "plane" },         // airplane
	{ 0x2709, "email" },         // envelope
	{ 0x270A, "fist" },          // raised fist
	{ 0x270B, "hand" },          // raised hand
	{ 0x270C, "peace" },         // victory hand
	{ 0x270D, "writing" },       // writing hand
	{ 0x2714, "/" },             // check mark
	{ 0x2716, "X" },             // cross mark
	{ 0x2733, "[*]" },           // eight spoked asterisk
	{ 0x2734, "[*]" },           // eight pointed star
	{ 0x274C, "X" },             // cross mark
	{ 0x274E, "X" },             // cross mark button
	{ 0x2753, "?" },             // red question mark
	{ 0x2754, "?" },             // white question mark
	{ 0x2755, "!" },             // white exclamation mark
	{ 0x2757, "!" },             // red exclamation mark
	{ 0x2763, "<3!" },           // heart exclamation
	{ 0x2764, "<3" },            // red heart
	{ 0x27A1, "->" },            // right arrow
	{ 0x2934, "^->" },           // right arrow curving up
	{ 0x2935, "v->" },           // right arrow curving down
	{ 0x2B05, "<-" },            // left arrow
	{ 0x2B06, "^" },             // up arrow
	{ 0x2B07, "v" },             // down arrow
	{ 0x2B50, "*" },             // star
	{ 0x2B55, "(o)" },           // hollow red circle
	{ 0x1F30D, "earth" },         // globe showing Europe-Africa
	{ 0x1F30E, "earth" },         // globe showing Americas
	{ 0x1F30F, "earth" },         // globe showing Asia-Australia
	{ 0x1F310, "earth" },         // globe with meridians
	{ 0x1F319, "moon" },          // crescent moon
	{ 0x1F31E, "sun" },           // sun with face
	{ 0x1F31F, "*" },             // glowing star
	{ 0x1F320, "*~" },            // shooting star
	{ 0x1F332, "tree" },          // evergreen tree
	{ 0x1F333, "tree" },          // deciduous tree
	{ 0x1F338, "blossom" },       // cherry blossom
	{ 0x1F37A, "beer" },          // beer mug
	{ 0x1F37B, "cheers" },        // clinking beer mugs
	{ 0x1F37D, "dining" },        // fork and knife with plate
	{ 0x1F37E, "champagne" },     // bottle with popping cork
	{ 0x1F381, "gift" },          // wrapped gift
	{ 0x1F382, "cake" },          // birthday cake
	{ 0x1F389, "party" },         // party popper
	{ 0x1F38A, "confetti" },      // confetti ball
	{ 0x1F38E, "dolls" },         // Japanese dolls
	{ 0x1F390, "windchime" },     // wind chime
	{ 0x1F3B5, "~*" },            // musical note
	{ 0x1F3B6, "~**" },           // musical notes
	{ 0x1F3B9, "piano" },         // musical keyboard
	{ 0x1F41D, "bee" },           // honeybee
	{ 0x1F41E, "ladybug" },       // lady beetle
	{ 0x1F431, ":3" },            // cat face
	{ 0x1F436, ":3" },            // dog face
	{ 0x1F44A, "fist" },          // oncoming fist
	{ 0x1F44B, "(wave)" },        // waving hand
	{ 0x1F44C, "ok" },            // OK hand
	{ 0x1F44D, "(+1)" },          // thumbs up
	{ 0x1F44E, "(-1)" },          // thumbs down
	{ 0x1F44F, "(clap)" },        // clapping hands
	{ 0x1F450, "hands" },         // open hands
	{ 0x1F47F, "}:[" },           // angry face with horns
	{ 0x1F48B, "kiss" },          // kiss mark
	{ 0x1F491, "<3 <3" },         // couple with heart
	{ 0x1F493, "<3*" },           // beating heart
	{ 0x1F494, "</3" },           // broken heart
	{ 0x1F495, "<3 <3" },         // two hearts
	{ 0x1F496, "<3*<3" },         // sparkling heart
	{ 0x1F497, "<3~" },           // growing heart
	{ 0x1F498, "<3-->" },         // heart with arrow
	{ 0x1F499, "<3" },            // blue heart
	{ 0x1F49A, "<3" },            // green heart
	{ 0x1F49B, "<3" },            // yellow heart
	{ 0x1F49C, "<3" },            // purple heart
	{ 0x1F49D, "[gift <3]" },     // heart with ribbon
	{ 0x1F49E, "<3 <3" },         // revolving hearts
	{ 0x1F49F, "<3" },            // heart decoration
	{ 0x1F4A1, "idea" },          // light bulb
	{ 0x1F4A2, "anger" },         // anger symbol
	{ 0x1F4A5, "boom" },          // collision
	{ 0x1F4A6, "splash" },        // sweat droplets
	{ 0x1F4A7, "sweat" },         // sweat droplets
	{ 0x1F4A8, "dash" },          // dashing away
	{ 0x1F4A9, "poop" },          // pile of poo
	{ 0x1F4AA, "flex" },          // flexed biceps
	{ 0x1F4AC, "speech" },        // speech balloon
	{ 0x1F4AD, "thought" },       // thought balloon
	{ 0x1F4AF, "100" },           // hundred points
	{ 0x1F4B0, "[$]" },           // money bag
	{ 0x1F4B8, "$~" },            // money with wings
	{ 0x1F4DE, "phone" },         // telephone receiver
	{ 0x1F4E7, "[@]" },           // email
	{ 0x1F4E8, "inbox" },         // incoming envelope
	{ 0x1F4E9, "outbox" },        // envelope with arrow
	{ 0x1F4F1, "mobile" },        // mobile phone
	{ 0x1F4F9, "video" },         // video camera
	{ 0x1F4FA, "tv" },            // television
	{ 0x1F576, "B)" },            // sunglasses
	{ 0x1F5A4, "<3" },            // black heart
	{ 0x1F600, ":D" },            // grinning face
	{ 0x1F601, "=D" },            // beaming face with smiling eyes
	{ 0x1F602, ":')" },           // face with tears of joy
	{ 0x1F603, ":D" },            // grinning face with big eyes
	{ 0x1F604, "=D" },            // grinning face with smiling eyes
	{ 0x1F605, "':D" },           // grinning face with sweat
	{ 0x1F606, "XD" },            // grinning squinting face
	{ 0x1F607, "O:)" },           // smiling face with halo
	{ 0x1F608, ">:)" },           // smiling face with horns
	{ 0x1F609, ";)" },            // winking face
	{ 0x1F60A, "=)" },            // smiling face with smiling eyes
	{ 0x1F60B, ":P~" },           // face savoring food
	{ 0x1F60C, "-_-" },           // relieved face
	{ 0x1F60D, "<3_<3" },         // smiling face with heart-eyes
	{ 0x1F60E, "B)" },            // smiling face with sunglasses
	{ 0x1F60F, "^.^" },           // smirking face
	{ 0x1F610, ":|" },            // neutral face
	{ 0x1F611, "-_-" },           // expressionless face
	{ 0x1F612, ":-/" },           // unamused face
	{ 0x1F613, "':(" },           // downcast face with sweat
	{ 0x1F614, ":-(" },           // pensive face
	{ 0x1F615, ":/" },            // confused face
	{ 0x1F616, ">.<" },           // confounded face
	{ 0x1F617, ":-*" },           // kissing face
	{ 0x1F618, ";-*" },           // face blowing a kiss
	{ 0x1F619, ":-*" },           // kissing face with smiling eyes
	{ 0x1F61A, ":-*" },           // kissing face with closed eyes
	{ 0x1F61B, ":P" },            // face with tongue
	{ 0x1F61C, ";P" },            // winking face with tongue
	{ 0x1F61D, "XP" },            // squinting face with tongue
	{ 0x1F61E, ":(" },            // disappointed face
	{ 0x1F61F, ":-[" },           // worried face
	{ 0x1F620, ">:(" },           // angry face
	{ 0x1F621, ">:[" },           // pouting face
	{ 0x1F622, ":'(" },           // crying face
	{ 0x1F623, ">_<" },           // persevering face
	{ 0x1F624, ">:{" },           // face with steam from nose
	{ 0x1F625, ":'[" },           // sad but relieved face
	{ 0x1F626, "D:" },            // frowning face with open mouth
	{ 0x1F627, "D;" },            // anguished face
	{ 0x1F628, "D8" },            // fearful face
	{ 0x1F629, ">.<" },           // weary face
	{ 0x1F62A, "~_~" },           // sleepy face
	{ 0x1F62B, ">_<" },           // tired face
	{ 0x1F62C, ":{" },            // grimacing face
	{ 0x1F62D, "T_T" },           // loudly crying face
	{ 0x1F62E, ":O" },            // face with open mouth
	{ 0x1F62F, ":o" },            // hushed face
	{ 0x1F630, "D:" },            // anxious face with sweat
	{ 0x1F631, "D:!" },           // face screaming in fear
	{ 0x1F632, "O_O" },           // astonished face
	{ 0x1F633, "o_o" },           // flushed face
	{ 0x1F634, "(-_-) zzZ" },     // sleeping face
	{ 0x1F635, "x_x" },           // face with crossed-out eyes
	{ 0x1F636, ":-X" },           // face without mouth
	{ 0x1F637, ":-#" },           // face with medical mask
	{ 0x1F638, ":3" },            // grinning cat with smiling eyes
	{ 0x1F639, ":'3" },           // cat with tears of joy
	{ 0x1F63A, ":3" },            // grinning cat
	{ 0x1F63B, "<3 :3" },         // smiling cat with heart-eyes
	{ 0x1F63C, ">:3" },           // cat with wry smile
	{ 0x1F63D, ":-* :3" },        // kissing cat
	{ 0x1F63E, ">:3" },           // pouting cat
	{ 0x1F63F, ":'3" },           // crying cat
	{ 0x1F640, "=o :3" },         // weary cat
	{ 0x1F641, ":(" },            // slightly frowning face
	{ 0x1F642, ":)" },            // slightly smiling face
	{ 0x1F643, "(:" },            // upside-down face
	{ 0x1F644, "9_9" },           // face with rolling eyes
	{ 0x1F648, "see no evil" },   // see-no-evil monkey
	{ 0x1F649, "hear no evil" },  // hear-no-evil monkey
	{ 0x1F64A, "speak no evil" }, // speak-no-evil monkey
	{ 0x1F64B, "\\\\\\\\o" },     // person raising hand
	{ 0x1F64C, "\\\\\\\\o/" },    // raising hands (celebration)
	{ 0x1F64D, ":-(" },           // person frowning
	{ 0x1F64F, "pray" },          // folded hands (prayer/thanks)
	{ 0x1F90D, "<3" },            // white heart
	{ 0x1F90E, "<3" },            // brown heart
	{ 0x1F910, ":-X" },           // zipper-mouth face
	{ 0x1F911, "$_$" },           // money-mouth face
	{ 0x1F912, "sick" },          // face with thermometer
	{ 0x1F913, "8-)" },           // nerd face
	{ 0x1F914, ":-?" },           // thinking face
	{ 0x1F915, "hurt" },          // face with head-bandage
	{ 0x1F917, "hug" },           // hugging face
	{ 0x1F918, "\\\\\\\\m/" },    // sign of the horns (rock on)
	{ 0x1F919, "call me" },       // call me hand
	{ 0x1F91A, "hand" },          // raised back of hand
	{ 0x1F91B, "fist L" },        // left-facing fist
	{ 0x1F91C, "fist R" },        // right-facing fist
	{ 0x1F91E, "crossed" },       // crossed fingers
	{ 0x1F91F, "love you" },      // love-you gesture
	{ 0x1F920, "cowboy" },        // cowboy hat face
	{ 0x1F921, ":o)" },           // clown face
	{ 0x1F922, ":-S" },           // nauseated face
	{ 0x1F923, "ROFL" },          // rolling on the floor laughing
	{ 0x1F924, ":P~~~" },         // drooling face
	{ 0x1F925, "liar" },          // lying face (Pinocchio)
	{ 0x1F926, "facepalm" },      // person facepalming
	{ 0x1F927, "sneeze" },        // sneezing face
	{ 0x1F928, "o_O" },           // face with raised eyebrow
	{ 0x1F929, "*_*" },           // star-struck
	{ 0x1F92A, ":P" },            // zany face
	{ 0x1F92B, ":-X" },           // shushing face
	{ 0x1F92C, ">:@" },           // face with symbols on mouth
	{ 0x1F92D, ":-$" },           // face with hand over mouth
	{ 0x1F92E, ":-&" },           // face vomiting
	{ 0x1F92F, "mind blown" },    // exploding head
	{ 0x1F942, "cheers" },        // clinking glasses
	{ 0x1F970, ":) <3" },         // smiling face with hearts
	{ 0x1F971, "yawn" },          // yawning face
	{ 0x1F972, ":')" },           // smiling face with tear
	{ 0x1F973, "party" },         // partying face
	{ 0x1F974, "%-)" },           // woozy face
	{ 0x1F975, "hot" },           // hot face
	{ 0x1F976, "cold" },          // cold face
	{ 0x1F979, ":'|" },           // face holding back tears
	{ 0x1F97A, "pleading" },      // pleading face
	{ 0x1F9D0, "monocle" },       // face with monocle
	{ 0x1F9E1, "<3" },            // orange heart
	{ 0x1FA75, "<3" },            // light blue heart
	{ 0x1FA76, "<3" },            // grey heart
	{ 0x1FA77, "<3" },            // pink heart
	{ 0x1FA79, "bandage" },       // adhesive bandage
	{ 0x1FAC0, "<3" },            // anatomical heart
	{ 0x1FAC8, "O_O" },           // face with open eyes and hand over mouth
	{ 0x1FAF6, "<3" },            // heart hands

};

static const size_t cSmileySubsSize = sizeof(cSmileySubs) / sizeof(SSmileySub);

#endif
