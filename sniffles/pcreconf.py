from sniffles.pcrecomp import *

IMM2_SIZE = 2
LINK_SIZE = 2

if PCRE_MINOR == 37 or PCRE_MINOR == 36 \
   or PCRE_MINOR == 34 or PCRE_MINOR == 35:
    OP_END = 0
    OP_SOD = 1
    OP_SOM = 2
    OP_SET_SOM = 3
    OP_NOT_WORD_BOUNDARY = 4
    OP_WORD_BOUNDARY = 5
    OP_NOT_DIGIT = 6
    OP_DIGIT = 7
    OP_NOT_WHITESPACE = 8
    OP_WHITESPACE = 9
    OP_NOT_WORDCHAR = 10
    OP_WORDCHAR = 11
    OP_ANY = 12
    OP_ALLANY = 13
    OP_ANYBYTE = 14
    OP_NOTPROP = 15
    OP_PROP = 16
    OP_ANYNL = 17
    OP_NOT_HSPACE = 18
    OP_HSPACE = 19
    OP_NOT_VSPACE = 20
    OP_VSPACE = 21
    OP_EXTUNI = 22
    OP_EODN = 23
    OP_EOD = 24
    OP_DOLL = 25
    OP_DOLLM = 26
    OP_CIRC = 27
    OP_CIRCM = 28
    OP_CHAR = 29
    OP_CHARI = 30
    OP_NOT = 31
    OP_NOTI = 32
    OP_STAR = 33
    OP_MINSTAR = 34
    OP_PLUS = 35
    OP_MINPLUS = 36
    OP_QUERY = 37
    OP_MINQUERY = 38
    OP_UPTO = 39
    OP_MINUPTO = 40
    OP_EXACT = 41
    OP_POSSTAR = 42
    OP_POSPLUS = 43
    OP_POSQUERY = 44
    OP_POSUPTO = 45
    OP_STARI = 46
    OP_MINSTARI = 47
    OP_PLUSI = 48
    OP_MINPLUSI = 49
    OP_QUERYI = 50
    OP_MINQUERYI = 51
    OP_UPTOI = 52
    OP_MINUPTOI = 53
    OP_EXACTI = 54
    OP_POSSTARI = 55
    OP_POSPLUSI = 56
    OP_POSQUERYI = 57
    OP_POSUPTOI = 58
    OP_NOTSTAR = 59
    OP_NOTMINSTAR = 60
    OP_NOTPLUS = 61
    OP_NOTMINPLUS = 62
    OP_NOTQUERY = 63
    OP_NOTMINQUERY = 64
    OP_NOTUPTO = 65
    OP_NOTMINUPTO = 66
    OP_NOTEXACT = 67
    OP_NOTPOSSTAR = 68
    OP_NOTPOSPLUS = 69
    OP_NOTPOSQUERY = 70
    OP_NOTPOSUPTO = 71
    OP_NOTSTARI = 72
    OP_NOTMINSTARI = 73
    OP_NOTPLUSI = 74
    OP_NOTMINPLUSI = 75
    OP_NOTQUERYI = 76
    OP_NOTMINQUERYI = 77
    OP_NOTUPTOI = 78
    OP_NOTMINUPTOI = 79
    OP_NOTEXACTI = 80
    OP_NOTPOSSTARI = 81
    OP_NOTPOSPLUSI = 82
    OP_NOTPOSQUERYI = 83
    OP_NOTPOSUPTOI = 84
    OP_TYPESTAR = 85
    OP_TYPEMINSTAR = 86
    OP_TYPEPLUS = 87
    OP_TYPEMINPLUS = 88
    OP_TYPEQUERY = 89
    OP_TYPEMINQUERY = 90
    OP_TYPEUPTO = 91
    OP_TYPEMINUPTO = 92
    OP_TYPEEXACT = 93
    OP_TYPEPOSSTAR = 94
    OP_TYPEPOSPLUS = 95
    OP_TYPEPOSQUERY = 96
    OP_TYPEPOSUPTO = 97
    OP_CRSTAR = 98
    OP_CRMINSTAR = 99
    OP_CRPLUS = 100
    OP_CRMINPLUS = 101
    OP_CRQUERY = 102
    OP_CRMINQUERY = 103
    OP_CRRANGE = 104
    OP_CRMINRANGE = 105
    OP_CRPOSSTAR = 106
    OP_CRPOSPLUS = 107
    OP_CRPOSQUERY = 108
    OP_CRPOSRANGE = 109
    OP_CLASS = 110
    OP_NCLASS = 111
    OP_XCLASS = 112
    OP_REF = 113
    OP_REFI = 114
    OP_DNREF = 115
    OP_DNREFI = 116
    OP_RECURSE = 117
    OP_CALLOUT = 118
    OP_ALT = 119
    OP_KET = 120
    OP_KETRMAX = 121
    OP_KETRMIN = 122
    OP_KETRPOS = 123
    OP_REVERSE = 124
    OP_ASSERT = 125
    OP_ASSERT_NOT = 126
    OP_ASSERTBACK = 127
    OP_ASSERTBACK_NOT = 128
    OP_ONCE = 129
    OP_ONCE_NC = 130
    OP_BRA = 131
    OP_BRAPOS = 132
    OP_CBRA = 133
    OP_CBRAPOS = 134
    OP_COND = 135
    OP_SBRA = 136
    OP_SBRAPOS = 137
    OP_SCBRA = 138
    OP_SCBRAPOS = 139
    OP_SCOND = 140
    OP_CREF = 141
    OP_DNCREF = 142
    OP_RREF = 143
    OP_DNRREF = 144
    OP_DEF = 145
    OP_BRAZERO = 146
    OP_BRAMINZERO = 147
    OP_BRAPOSZERO = 148
    OP_MARK = 149
    OP_PRUNE = 150
    OP_PRUNE_ARG = 151
    OP_SKIP = 152
    OP_SKIP_ARG = 153
    OP_THEN = 154
    OP_THEN_ARG = 155
    OP_COMMIT = 156
    OP_FAIL = 157
    OP_ACCEPT = 158
    OP_ASSERT_ACCEPT = 159
    OP_CLOSE = 160
    OP_SKIPZERO = 161

    PCRE_OPLEN = [
        1,
        1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1,
        1, 1, 1,
        3, 3,
        1, 1, 1, 1, 1,
        1,
        1, 1, 1, 1, 1, 1,
        2,
        2,
        2,
        2,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        1, 1, 1, 1, 1, 1,
        1 + 2 * IMM2_SIZE, 1 + 2 * IMM2_SIZE,
        1, 1, 1, 1 + 2 * IMM2_SIZE,
        1 + (32 / 1),
        1 + (32 / 1),
        0,
        1 + IMM2_SIZE,
        1 + IMM2_SIZE,
        1 + 2 * IMM2_SIZE,
        1 + 2 * IMM2_SIZE,
        1 + LINK_SIZE,
        2 + 2 * LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE,
        1 + IMM2_SIZE, 1 + 2 * IMM2_SIZE,
        1 + IMM2_SIZE, 1 + 2 * IMM2_SIZE,
        1,
        1, 1, 1,
        3, 1, 3,
        1, 3,
        1, 3,
        1, 1, 1, 1,
        1 + IMM2_SIZE, 1
    ]
elif PCRE_MINOR == 33 or PCRE_MINOR == 31:
    OP_END = 0
    OP_SOD = 1
    OP_SOM = 2
    OP_SET_SOM = 3
    OP_NOT_WORD_BOUNDARY = 4
    OP_WORD_BOUNDARY = 5
    OP_NOT_DIGIT = 6
    OP_DIGIT = 7
    OP_NOT_WHITESPACE = 8
    OP_WHITESPACE = 9
    OP_NOT_WORDCHAR = 10
    OP_WORDCHAR = 11
    OP_ANY = 12
    OP_ALLANY = 13
    OP_ANYBYTE = 14
    OP_NOTPROP = 15
    OP_PROP = 16
    OP_ANYNL = 17
    OP_NOT_HSPACE = 18
    OP_HSPACE = 19
    OP_NOT_VSPACE = 20
    OP_VSPACE = 21
    OP_EXTUNI = 22
    OP_EODN = 23
    OP_EOD = 24
    OP_CIRC = 25
    OP_CIRCM = 26
    OP_DOLL = 27
    OP_DOLLM = 28
    OP_CHAR = 29
    OP_CHARI = 30
    OP_NOT = 31
    OP_NOTI = 32
    OP_STAR = 33
    OP_MINSTAR = 34
    OP_PLUS = 35
    OP_MINPLUS = 36
    OP_QUERY = 37
    OP_MINQUERY = 38
    OP_UPTO = 39
    OP_MINUPTO = 40
    OP_EXACT = 41
    OP_POSSTAR = 42
    OP_POSPLUS = 43
    OP_POSQUERY = 44
    OP_POSUPTO = 45
    OP_STARI = 46
    OP_MINSTARI = 47
    OP_PLUSI = 48
    OP_MINPLUSI = 49
    OP_QUERYI = 50
    OP_MINQUERYI = 51
    OP_UPTOI = 52
    OP_MINUPTOI = 53
    OP_EXACTI = 54
    OP_POSSTARI = 55
    OP_POSPLUSI = 56
    OP_POSQUERYI = 57
    OP_POSUPTOI = 58
    OP_NOTSTAR = 59
    OP_NOTMINSTAR = 60
    OP_NOTPLUS = 61
    OP_NOTMINPLUS = 62
    OP_NOTQUERY = 63
    OP_NOTMINQUERY = 64
    OP_NOTUPTO = 65
    OP_NOTMINUPTO = 66
    OP_NOTEXACT = 67
    OP_NOTPOSSTAR = 68
    OP_NOTPOSPLUS = 69
    OP_NOTPOSQUERY = 70
    OP_NOTPOSUPTO = 71
    OP_NOTSTARI = 72
    OP_NOTMINSTARI = 73
    OP_NOTPLUSI = 74
    OP_NOTMINPLUSI = 75
    OP_NOTQUERYI = 76
    OP_NOTMINQUERYI = 77
    OP_NOTUPTOI = 78
    OP_NOTMINUPTOI = 79
    OP_NOTEXACTI = 80
    OP_NOTPOSSTARI = 81
    OP_NOTPOSPLUSI = 82
    OP_NOTPOSQUERYI = 83
    OP_NOTPOSUPTOI = 84
    OP_TYPESTAR = 85
    OP_TYPEMINSTAR = 86
    OP_TYPEPLUS = 87
    OP_TYPEMINPLUS = 88
    OP_TYPEQUERY = 89
    OP_TYPEMINQUERY = 90
    OP_TYPEUPTO = 91
    OP_TYPEMINUPTO = 92
    OP_TYPEEXACT = 93
    OP_TYPEPOSSTAR = 94
    OP_TYPEPOSPLUS = 95
    OP_TYPEPOSQUERY = 96
    OP_TYPEPOSUPTO = 97
    OP_CRSTAR = 98
    OP_CRMINSTAR = 99
    OP_CRPLUS = 100
    OP_CRMINPLUS = 101
    OP_CRQUERY = 102
    OP_CRMINQUERY = 103
    OP_CRRANGE = 104
    OP_CRMINRANGE = 105
    OP_CLASS = 106
    OP_NCLASS = 107
    OP_XCLASS = 108
    OP_REF = 109
    OP_REFI = 110
    OP_RECURSE = 111
    OP_CALLOUT = 112
    OP_ALT = 113
    OP_KET = 114
    OP_KETRMAX = 115
    OP_KETRMIN = 116
    OP_KETRPOS = 117
    OP_REVERSE = 118
    OP_ASSERT = 119
    OP_ASSERT_NOT = 120
    OP_ASSERTBACK = 121
    OP_ASSERTBACK_NOT = 122
    OP_ONCE = 123
    OP_ONCE_NC = 124
    OP_BRA = 125
    OP_BRAPOS = 126
    OP_CBRA = 127
    OP_CBRAPOS = 128
    OP_COND = 129
    OP_SBRA = 130
    OP_SBRAPOS = 131
    OP_SCBRA = 132
    OP_SCBRAPOS = 133
    OP_SCOND = 134
    OP_CREF = 135
    OP_NCREF = 136
    OP_RREF = 137
    OP_NRREF = 138
    OP_DEF = 139
    OP_BRAZERO = 140
    OP_BRAMINZERO = 141
    OP_BRAPOSZERO = 142
    OP_MARK = 143
    OP_PRUNE = 144
    OP_PRUNE_ARG = 145
    OP_SKIP = 146
    OP_SKIP_ARG = 147
    OP_THEN = 148
    OP_THEN_ARG = 149
    OP_COMMIT = 150
    OP_FAIL = 151
    OP_ACCEPT = 152
    OP_ASSERT_ACCEPT = 153
    OP_CLOSE = 154
    OP_SKIPZERO = 155

    # Symbols introduced in 8.34
    OP_CRPOSPLUS = 250
    OP_CRPOSQUERY = 251
    OP_CRPOSRANGE = 252
    OP_CRPOSSTAR = 253

    PCRE_OPLEN = [
        1,
        1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1,
        1, 1, 1,
        3, 3,
        1, 1, 1, 1, 1,
        1,
        1, 1, 1, 1, 1, 1,
        2,
        2,
        2,
        2,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        2, 2, 2, 2, 2, 2,
        2 + IMM2_SIZE, 2 + IMM2_SIZE,
        2 + IMM2_SIZE,
        2, 2, 2, 2 + IMM2_SIZE,
        1, 1, 1, 1, 1, 1,
        1 + 2 * IMM2_SIZE, 1 + 2 * IMM2_SIZE,
        1 + (32 / 1),
        1 + (32 / 1),
        0,
        1 + IMM2_SIZE,
        1 + IMM2_SIZE,
        1 + LINK_SIZE,
        2 + 2 * LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE + IMM2_SIZE,
        1 + LINK_SIZE,
        1 + IMM2_SIZE, 1 + IMM2_SIZE,
        1 + IMM2_SIZE, 1 + IMM2_SIZE,
        1,
        1, 1, 1,
        3, 1, 3,
        1, 3,
        1, 3,
        1, 1, 1, 1,
        1 + IMM2_SIZE, 1
    ]
elif PCRE_MINOR == 12:
    OP_END = 0
    OP_SOD = 1
    OP_SOM = 2
    OP_SET_SOM = 3
    OP_NOT_WORD_BOUNDARY = 4
    OP_WORD_BOUNDARY = 5
    OP_NOT_DIGIT = 6
    OP_DIGIT = 7
    OP_NOT_WHITESPACE = 8
    OP_WHITESPACE = 9
    OP_NOT_WORDCHAR = 10
    OP_WORDCHAR = 11
    OP_ANY = 12
    OP_ALLANY = 13
    OP_ANYBYTE = 14
    OP_NOTPROP = 15
    OP_PROP = 16
    OP_ANYNL = 17
    OP_NOT_HSPACE = 18
    OP_HSPACE = 19
    OP_NOT_VSPACE = 20
    OP_VSPACE = 21
    OP_EXTUNI = 22
    OP_EODN = 23
    OP_EOD = 24
    OP_OPT = 25
    OP_CIRC = 26
    OP_DOLL = 27
    OP_CHAR = 28
    OP_CHARNC = 29
    OP_NOT = 30
    OP_STAR = 31
    OP_MINSTAR = 32
    OP_PLUS = 33
    OP_MINPLUS = 34
    OP_QUERY = 35
    OP_MINQUERY = 36
    OP_UPTO = 37
    OP_MINUPTO = 38
    OP_EXACT = 39
    OP_POSSTAR = 40
    OP_POSPLUS = 41
    OP_POSQUERY = 42
    OP_POSUPTO = 43
    OP_NOTSTAR = 44
    OP_NOTMINSTAR = 45
    OP_NOTPLUS = 46
    OP_NOTMINPLUS = 47
    OP_NOTQUERY = 48
    OP_NOTMINQUERY = 49
    OP_NOTUPTO = 50
    OP_NOTMINUPTO = 51
    OP_NOTEXACT = 52
    OP_NOTPOSSTAR = 53
    OP_NOTPOSPLUS = 54
    OP_NOTPOSQUERY = 55
    OP_NOTPOSUPTO = 56
    OP_TYPESTAR = 57
    OP_TYPEMINSTAR = 58
    OP_TYPEPLUS = 59
    OP_TYPEMINPLUS = 60
    OP_TYPEQUERY = 61
    OP_TYPEMINQUERY = 62
    OP_TYPEUPTO = 63
    OP_TYPEMINUPTO = 64
    OP_TYPEEXACT = 65
    OP_TYPEPOSSTAR = 66
    OP_TYPEPOSPLUS = 67
    OP_TYPEPOSQUERY = 68
    OP_TYPEPOSUPTO = 69
    OP_CRSTAR = 70
    OP_CRMINSTAR = 71
    OP_CRPLUS = 72
    OP_CRMINPLUS = 73
    OP_CRQUERY = 74
    OP_CRMINQUERY = 75
    OP_CRRANGE = 76
    OP_CRMINRANGE = 77
    OP_CLASS = 78
    OP_NCLASS = 79
    OP_XCLASS = 80
    OP_REF = 81
    OP_RECURSE = 82
    OP_CALLOUT = 83
    OP_ALT = 84
    OP_KET = 85
    OP_KETRMAX = 86
    OP_KETRMIN = 87
    OP_ASSERT = 88
    OP_ASSERT_NOT = 89
    OP_ASSERTBACK = 90
    OP_ASSERTBACK_NOT = 91
    OP_REVERSE = 92
    OP_ONCE = 93
    OP_BRA = 94
    OP_CBRA = 95
    OP_COND = 96
    OP_SBRA = 97
    OP_SCBRA = 98
    OP_SCOND = 99
    OP_CREF = 100
    OP_NCREF = 101
    OP_RREF = 102
    OP_NRREF = 103
    OP_DEF = 104
    OP_BRAZERO = 105
    OP_BRAMINZERO = 106
    OP_MARK = 107
    OP_PRUNE = 108
    OP_PRUNE_ARG = 109
    OP_SKIP = 110
    OP_SKIP_ARG = 111
    OP_THEN = 112
    OP_THEN_ARG = 113
    OP_COMMIT = 114
    OP_FAIL = 115
    OP_ACCEPT = 116
    OP_CLOSE = 117
    OP_SKIPZERO = 118

    # Symbols introduced in 8.34
    OP_CRPOSPLUS = 250
    OP_CRPOSQUERY = 251
    OP_CRPOSRANGE = 252
    OP_CRPOSSTAR = 253

    PCRE_OPLEN = [
        1,
        1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1,
        1, 1, 1,
        3, 3,
        1, 1, 1, 1, 1,
        1,
        1, 1, 2, 1, 1,
        2,
        2,
        2,
        2, 2, 2, 2, 2, 2,
        4, 4, 4,
        2, 2, 2, 4,
        2, 2, 2, 2, 2, 2,
        4, 4, 4,
        2, 2, 2, 4,
        2, 2, 2, 2, 2, 2,
        4, 4, 4,
        2, 2, 2, 4,
        1, 1, 1, 1, 1, 1,
        5, 5,
        33,
        33,
        0,
        3,
        1 + LINK_SIZE,
        2 + 2 * LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        3 + LINK_SIZE,
        1 + LINK_SIZE,
        1 + LINK_SIZE,
        3 + LINK_SIZE,
        1 + LINK_SIZE,
        3, 3,
        3, 3,
        1,
        1, 1,
        3, 1, 3,
        1, 3,
        1 + LINK_SIZE, 3 + LINK_SIZE,
        1, 1, 1, 3, 1
    ]
