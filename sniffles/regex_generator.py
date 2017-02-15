import getopt
import sys
import datetime
import re
import random
import sniffles.pcrecomp
from sniffles.nfa import PCRE_CASELESS, PCRE_DOTALL, PCRE_MULTILINE, PCRE_OPT

"""
  regex_generator.  This is a simple regular expression generator.
  It creates regular expressions either completely randomly, or
  based on a serires of distributions.
  The controls that can be placed on how the regular expressions are
  generated are structural rather than contextual.  In other words,
  there is no effort to make certain string tokens appear in
  the generated regular expressions.  However, the probability
  distributions can be tweeked to affect the types of features
  found in the rules like character classes, alternation, repetition,
  etc.
"""


##############################################################################
# Main Processing
##############################################################################
def main():
    number = 1
    lambd = 65                         # Based on average rule size
    type_dist = [85, 10, 5]            # Mostly chars, rest classes and alt
    char_dist = [15, 10, 30, 30, 15]   # Emphasis on digits and alpha
    class_dist = [50, 50]
    groups = False
    rep_dist = [15, 30, 30, 25]        # Emphasis on * and +
    rep_chance = 5
    option_chance = 20
    negation_prob = 15
    min_regex_length = 3             # Default to regex at least 3 chars in len
    max_regex_length = 0             # Default to zero(max_length not applied)
    re_file = "rand.re"
    cmd_options = "C:c:D:f:gl:M:m:n:o:R:r:t:?"
    try:
        options, args = getopt.getopt(sys.argv[1:], cmd_options, [])
    except getopt.GetoptError as err:
        print("Error: ", err)
        usage()
    for opt, arg in options:
        if opt == "-C":
            if arg is not None:
                char_dist = re.split('[\s,;]*', arg)
        elif opt == "-D":
            if arg is not None:
                class_dist = re.split('[\s,;]*', arg)
        elif opt == "-c":
            number = int(arg)
            if number <= 0:
                number = 1
        elif opt == "-f":
            if arg is not None:
                re_file = arg
        elif opt == "-g":
            groups = True
        elif opt == "-l":
            lambd = int(arg)
            if lambd <= 0:
                lambd = 10
        elif opt == "-M":
            if arg is not None:
                max_regex_length = int(arg)
        elif opt == "-m":
            min_regex_length = int(arg)
            if min_regex_length < 1:
                min_regex_length = 1
        elif opt == "-n":
            negation_prob = int(arg)
            if negation_prob < 0:
                negation_prob = 0
        elif opt == "-o":
            option_chance = int(arg)
            if option_chance < 0:
                option_chance = 0
        elif opt == "-R":
            rep_chance = int(arg)
            if rep_chance < 0:
                rep_chance = 0
        elif opt == "-r":
            if arg is not None:
                rep_dist = re.split('[\s,;]*', arg)
        elif opt == "-t":
            if arg is not None:
                type_dist = re.split('[\s,;]*', arg)
        elif opt == "-?":
            usage()
        else:
            print("Unrecognized Option: ", opt)
            usage()
    create_regex_list(number, lambd, type_dist, char_dist, class_dist,
                      rep_dist, rep_chance, option_chance, negation_prob,
                      re_file, min_regex_length, max_regex_length, groups)
    print("Finished creating random regular expressions.")
    sys.exit(0)

##############################################################################
# End Main Processing
##############################################################################

##############################################################################
# Support Functions
##############################################################################


def create_regex_list(number, lambd, type_dist, char_dist, class_dist,
                      rep_dist, rep_chance, option_chance, negation_prob,
                      re_file, min_regex_length, max_regex_length,
                      groups=False):
    """Manages the creation of the new regular expression list.
    Steps invloved:
      1. Create the regex.
      2. Decorate the regex with / and possible options.
      3. Append each regex to regex list.
      4. Ultimately write out all regex to the output file.
    """
    myrelist = []
    mygroups = []
    if groups and number > 1:
        mygroups = getREGroups(number, type_dist, char_dist,
                               class_dist, rep_dist, rep_chance, negation_prob,
                               min_regex_length)

    count = 0
    while count < number:
        myregex = '/'
        if mygroups:
            myregex += mygroups[random.randint(0, len(mygroups) - 1)]
        myregex += generate_regex(lambd, max_regex_length, type_dist,
                                  char_dist, class_dist, rep_dist, rep_chance,
                                  negation_prob, min_regex_length)
        myregex += '/'
        pick = random.randint(0, 100)
        if pick < option_chance:
            options = ['i', 's', 'm']
            total_opts = random.randint(1, len(options))
            random.shuffle(options)
            myoptions = options[0:total_opts]
            for o in myoptions:
                myregex += o
        # check if this compiles or not
        if not check_pcre_compile(myregex):
            # pcre compile failed. give another try until it passes
            continue
        myregex += "\n"
        myrelist.append(myregex)
        count += 1
    fd = open(re_file, 'wb')
    for re in myrelist:
        fd.write(bytes(re, 'UTF-8'))
    fd.close()


def generate_regex(lambd, max_len, type_dist, char_dist,
                   class_dist, rep_dist, rep_chance,
                   negation_prob, min_regex_length):
    """Creates a regular expression.

    Lambda designates the mean of the length of the regular expression
    using an exponentially determined random number.  The length of
    the regular expression is not the length in characters, but the
    length in structures with a structure being either a character,
    character class, or alternation.  This function is called
    recursively from the get_alternation() function thus, if the
    max_len variable is larger than 0, then it is assumed that this is
    a recursive call and max_len is used as the length.  This function
    will continue concatenating structures to the regular expression
    until the entire length has been generated.  Note: the minimum
    regex lenght is fixed at 3 characters (with possible decoration
    i.e. repetition).
    """
    if lambd <= 0:
        lambd = 10
    mylen = int(random.expovariate(1/lambd))

    if mylen < min_regex_length:
        mylen = min_regex_length
    if max_len > 0 and mylen > max_len:
        mylen = max_len

    total_types = 3
    index = 0
    myregex = ''
    i = 0
    while i < mylen:
        next = ''
        index = get_index(total_types, type_dist)
        if index == 0:
            myregex += get_char(char_dist)
        elif index == 1:
            myregex += get_class(class_dist, negation_prob, char_dist)
        elif index == 2:
            max_len = random.randint(1, mylen-i)
            i += max_len
            if max_len > 1:
                i -= 1
            myregex += get_alternation(max_len, type_dist, char_dist,
                                       class_dist, rep_dist, rep_chance,
                                       negation_prob)
        else:
            myregex += get_char(char_dist)
        pick = random.randint(0, 99)
        if pick < rep_chance:
            myregex += get_repetition(rep_dist)
        i += 1
    return myregex


def get_char(char_dist):
    """Determines which character type to return.

    This is the base content generation function for the regex.  If
    more advanced content generation is desired, this function should
    be modified.
    """
    total_char_options = 5
    index = get_index(total_char_options, char_dist)
    mychar = ""
    if index == 0:
        mychar = get_ascii_char()
    elif index == 1:
        mychar = get_bin_char()
    elif index == 2:
        mychar = get_letter()
    elif index == 3:
        mychar = get_digit()
    elif index == 4:
        mychar = get_substitution_class()
    else:
        mychar = get_ascii_char()
    return mychar


def get_ascii_char():
    """Get ASCII will return a printable ASCII character.  If that
    character might cause issues with a regex (i.e. is a character
    that has meaning like *) then it will be re-written in binary
    form.
    """
    bad_chars = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
                 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94, 96, 123, 124,
                 125, 126, 127]
    pick = random.randint(32, 127)
    if pick in bad_chars:
        return "\\x%0.2X" % pick
    return chr(pick)


def get_bin_char():
    pick = random.randint(0, 255)
    return "\\x%0.2X" % pick


def get_substitution_class():
    pick = random.randint(0, 6)

    if pick == 0:
        mysubstitution = '\d'
    elif pick == 1:
        mysubstitution = '\s'
    elif pick == 2:
        mysubstitution = '\w'
    elif pick == 3:
        mysubstitution = '\D'
    elif pick == 4:
        mysubstitution = '\S'
    elif pick == 5:
        mysubstitution = '\W'
    elif pick == 6:
        mysubstitution = '.'
    else:
        mysubstitution = '.'
    return mysubstitution


def get_digit():
    pick = random.randint(ord('0'), ord('9'))
    return chr(pick)


def get_letter():
    char_tbl = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
                'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                'Y', 'Z']
    chr_pick = random.choice(char_tbl)

    upper_lower = random.randint(0, 100)
    if upper_lower < 50:
        chr_pick = chr_pick.lower()
    return chr_pick


def get_class(class_distribution, negation_prob, char_dist):
    """This function will attempt to build an ad-hoc class of characters.
    Minimal effort is made to avoid duplicates.  Thus, it is possible,
    for ranges at least, that two ranges overlap.
    """
    total_class_choices = 2
    index = get_index(total_class_choices, class_distribution)
    class_set = []
    myclass = '['
    neg = False
    pick = random.randint(0, 99)
    if pick < negation_prob:
        myclass += '^'
        neg = True
    if index == 0:
        end = random.randint(1, 5)
        for i in range(0, end):
            next_char = get_char(char_dist)
            while next_char == '.':
                next_char = get_char(char_dist)
            if next_char not in class_set:
                class_set.append(next_char)
            else:
                i -= 1
    elif index == 1:
        start = get_letter()
        end = 0
        if ord(start) >= 122:
            start = chr(121)
            end = 122
        elif ord(start) >= 90:
            start = chr(89)
            end = 90
        else:
            if (ord(start) - 64) > 0 and (ord(start) - 64) < 26:
                end = random.randint(ord(start)+1, ord(start) +
                                     (26 - (ord(start) - 64)))
            elif (ord(start) - 96) > 0:
                end = random.randint(ord(start)+1, ord(start) +
                                     (26 - (ord(start) - 96)))
            else:
                end = ord(start)+1
        next_char = start + '-' + chr(end)
        class_set.append(next_char)
    else:
        end = random.randint(1, 5)
        for i in range(0, end):
            next_char = get_char(char_dist)
            while next_char == '.':
                next_char = get_char(char_dist)
            if next_char not in class_set:
                class_set.append(next_char)
            else:
                i -= 1

    for c in class_set:
        if neg and c in ['\W', '\D', '\S']:
            continue
        myclass += c
    if myclass == '[' or myclass == '[^':
        myclass += 'a-z'
    myclass += ']'
    return myclass


def get_alternation(max_length, type_dist, char_dist,
                    class_dist, rep_dist, rep_chance, negation_prob):
    """This will create a set of alternates potentially up to the maximum
    length provided.  The length of the alternation (alt_max_length)
    denotes the length of the longest path of alternation.  The number
    of alternates in one set of alternation is exponentially
    distributed with a mean of 2.  Alternation will simply call the
    generate_regex() function to generate the structure and content of
    each alternate.
    """
    myalternation = '('
    alternates = int(random.expovariate(1/2))
    alt_max_length = random.randint(1, max_length)
    if alternates <= 1:
        alternates = 2
    for i in range(0, alternates):
        this_length = alt_max_length
        if i > 0:
            this_length = random.randint(1, alt_max_length)
        myalternation += generate_regex(0, this_length, type_dist, char_dist,
                                        class_dist, rep_dist, rep_chance,
                                        negation_prob, 1)
        if i < alternates - 1:
            myalternation += '|'
    myalternation += ')'
    return myalternation


def get_index(total_options, dist):
    """This function is used to determine what index of a given
    distribution is returned.
    """
    if total_options <= 0:
        total_options = 1
    if dist is None:
        return random.randint(0, total_options-1)
    else:
        index = 0
        sum = 0
        pick = random.randint(0, 99)
        for prob in dist:
            sum += int(prob)
            if pick < sum:
                return index
            else:
                index += 1


def get_repetition(rep_dist, rep_start_max=5, rep_end_max=10):
    total_repetion = 4
    index = get_index(total_repetion, rep_dist)

    myrep = ''
    if index == 0:
        myrep = '?'
    elif index == 1:
        myrep = '*'
    elif index == 2:
        myrep = '+'
    elif index == 3:
        start = random.randint(0, rep_start_max)
        end = random.randint(start + 1, rep_end_max)
        myrep = '{' + str(start) + ',' + str(end) + '}'
    else:
        myrep = '*'
    return myrep


def getREGroups(number, type_dist, char_dist, class_dist,
                rep_dist, rep_chance, negation_prob, min_regex_len):
    new_groups = []
    if number > 1:
        num_groups = random.randint(1, int(number/2))
        for i in range(1, num_groups):
            prefix = generate_regex(random.randint(5, 20), 0,
                                    type_dist, char_dist, class_dist, rep_dist,
                                    rep_chance, negation_prob, 1)
            new_groups.append(prefix)
    return new_groups


def check_pcre_compile(re):
    options = []
    if len(re) and re[0] == '/':
        optp = re.rfind('/')
        if optp > 0:
            options = list(re[optp + 1:])
            re = re[1:optp]
    opts = 0
    for opt in options:
        if opt in PCRE_OPT:
            opts |= PCRE_OPT[opt]
    try:
        sniffles.pcrecomp.compile(re, opts)
    except:
        return False
    return True


def usage():
    usage_stmt = """regex_generator--Random Regular Expression Generator.
    usage: regex_generator.py [-C char distribution] [-c number regex]
    [-D class distribution] [-f output re file]
    [-l lambda for length generation] [-M maximum regex length]
	[-m minimum regex length] [-n negation probability]
    [-o options chance] [-R repetition chance] [-r repetition distribution]
    [-t re structural type distribution] [-?] [-g]

    -C \t Character Distribution: This sets the possibility of seeing
    particular constructs or characters.  See a brief explanation of
    distibutions below for examples on how to use this.  The default
    distribution puts some emphasis on alphabet and number characters.
    This distribution has five slots: ASCII Characters, Binary characters
    in \x00 (hex) format, Alphabetical letters (upper or lower case),
    Digits, and substitution classes (like \w).
    An example input to this would be "10,20,10,40,20"
    which would mean 10% chance any generated chae would come from ASCII,
    20% binary, 10% letters, etc.  One Caveat is that ASCII chars that
    might cause problems with regular expressions (like `[' or '{')
    are converted to hex representation (\x3b for example).
    -c \t number of regular expression to generate.  Default is one.
    -D \t Class Distribution: There are only two slots in the class
    distribution.  The first slot is the probability that the class is
    comprised of some number of randomly generated character.  The
    second slot is the probability that the class is comprised of
    ranges (like a-z).
    -f \t output file name.  This sets the name of the file where the
    regular expressions are stored.  The default is a file named rand.re
    in the current working directory.
    -g \t Groups: All regular expressions will have a common prefix with
    at least one or more other regular expressions (as long as there are
    more than one regex.)  A common prefix is just a regular expression
    that is the same for some set of regular expressions.  The total
    number of possible common prefixes is from 1 to 1/2 the size of the
    total regular expressions to generate.  The default value for this
    is false.  This option takes no parameters.
    -l \t lambda for length:  This is the mean length for an exponentional
    distribution of regular expression lengths.  The default value is 65
    (derived from the average regex length taken from several regular
    expression sets used in computer security).
	-M \t Maximum Regex Length: make regular expressions at most this
    structural length or shorter. By default, maximum length is not limited.
    -m \t Minimum Regex Length: make regular expressions at least this
    this length or longer.  Defaults to 3, and will automatically use a
    value of 1 if the input is zero or less.
    -n \t negation probability: The probability that a character class will
    be a negation class ([^xyz]) rather than a normal character class ([xyz]).
    Default probability is 15% (arbitrarily set).
    -o \t option chance:  This is the chance for an option to be appended
    to the regular expression.  Current options are 'i', 'm', and 's'.
    If options are appended to a regular expression one or more are
    appended.  The default chance is 20%.
    -R \t repetition chance: The chance of repetition occuring after
    any structural component has been added to the regular expression.
    The default value is 5% which is roughly the amount of repetition
    seen in the regular expression files we have examined.
    -r \t repetion distribution: The distribution of repetition structures.
    The slots are: Zero to one (?), Zero to many (*), one to many (+), and
    counting ({x,y}).  The default distribution favors * and +.
    -t \t Re structural type distribution: The distribution for the
    primary structural components of the regular expression.  These
    are comprised of three slots, or categories: characters, classes,
    and alternation.  Note, alternation will simply generate a smaller
    regular expression up to the size of the remaining length left to
    the re.  In other words, alternation will result in several smaller
    regular expressions being joined into the overall regular expression.
    The alternation uses the exact same methodology in creating those
    smaller regular expressions.  The default distribution of these
    types is 85% characters, 10% classes, and 5% alternation.  These
    values were derived from the regular expression sets we examined.
    -? \t print this help.

    This generator will create random regular expressions.  It is possible
    to tune the structures within the regular expressions to a prbability
    distribution, but currently not the content.  This is desirable in
    order to explore the maximum diversity in possible regular expressions
    (though not necessarily realistic regular expressions).
    The distributions are handled by creating a list of probabilities for
    the various possibilities, or slots, for a particular distribution.
    These are added as command line arguments using a simple string
    list like: "10,30,40,20".  The list should have as many values
    as it has slots.  The total of all values in the list should be
    100 and there should not be any fractions.  The value at each slot
    is the probability that that slot will be chosen.  For example,
    the base RE structural type distribution has three slots.  The
    first slot is the probability that the next structure type is
    a character (where a character can be a letter, digit, binary, ASCII,
    or substitution class (like \w).  The second slot is for character
    classes like [ab@%], [^123], or [a-z].  The final slot is the probability
    of alternation occuring like (ab|cd).  With these three slots you can tune
    how often you would like the structures to appear in your regular
    expressions.  For example, python3.4 -c 10 -t "80,10,10" would create
    10 regular expressions where 80% of the structures used would be
    characters, 10 percent would be character classes, and 10% alternation.
    """
    print(usage_stmt)

    sys.exit(0)

if __name__ == "__main__":
    main()
