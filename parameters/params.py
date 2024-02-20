"""
Parameter sets for 

# Small example parameters for debugging and testing
FESTA_TOY

# FESTA parameters which aim to target NIST levels I, III and V
FESTA_128
FESTA_192
FESTA_256
"""

from sage.all import ZZ

# ====================================== #
#          FESTA Parameter Sets          #
# ====================================== #

festa_params_toy = {
    "p": ZZ(
        7545361454103850395661596729552781781066711446878709645773968236168692864673072676413314730290220114782761341176503300436072791276654751987277883305944315592703999
    ),
    "l": ZZ(2),
    "b": ZZ(212),
    "f": ZZ(99),
    "d1": ZZ(415709681189302716705144249507062872921),
    "d2": ZZ(732304420484977534689364942307555175375),
    "dA": ZZ(1446798196833488661421576908672180025081),
    "dA1": ZZ(5488035898275841),
    "dA2": ZZ(263627684594414680571641),
    "m1": ZZ(52919),
    "m2": ZZ(1),
    "T1": ZZ(2281429653627698417035694373241693546061737847987401561),
    "T2": ZZ(193055718790709282445965536491355191078652217638507653006540375),
    "window": [ZZ(14)],
    "lambda_security": 64,
}

festa_params_128 = {
    "p": ZZ(
        47024755958377559820179144403517951365146739428682715587273315623743750596061899792398466078144401013185715861778663433311982543504793487377320505349521764013889738945943941940719288568009419068532558629959602395774408311593047625247205227520083266453579670098107898431221700871924390803878116783902285625847004174086777944844067095845116835903577335827518413153233468762445855819038719999
    ),
    "l": ZZ(2),
    "b": ZZ(632),
    "f": ZZ(107),
    "d1": ZZ(
        3**6
        * 19**2
        * 29**2
        * 37**2
        * 83**2
        * 139**2
        * 167**2
        * 251**2
        * 419**2
        * 421**2
        * 701**2
        * 839**2
        * 1009**2
        * 1259**2
        * 3061**2
        * 3779**2
    ),
    "d2": ZZ(
        5**4
        * 7**3
        * 11**2
        * 13**2
        * 17**2
        * 41**2
        * 43**2
        * 71**2
        * 89**2
        * 127**2
        * 211**2
        * 281**2
        * 503**2
        * 631**2
        * 2309**2
        * 2521**2
        * 2647**2
        * 2729**2
    ),
    "dA": ZZ(
        59**2
        * 3023**2
        * 3359**2
        * 4409**2
        * 5039**2
        * 6299**2
        * 6719**2
        * 9181**2
        * 19531**2
        * 22679**2
        * 41161**2
    ),
    "dA1": ZZ(59**2 * 6299**2 * 6719**2 * 9181**2),
    "dA2": ZZ(
        3023**2
        * 3359**2
        * 4409**2
        * 5039**2
        * 19531**2
        * 22679**2
        * 41161**2
    ),
    "m1": ZZ(1492184945093476592520242083925044182103921),
    "m2": ZZ(25617331336429939300166693069),
    "T1": ZZ(
        3**6
        * 19**2
        * 29**2
        * 37**2
        * 59**2
        * 83**2
        * 139**2
        * 167**2
        * 251**2
        * 419**2
        * 421**2
        * 701**2
        * 839**2
        * 1009**2
        * 1259**2
        * 3061**2
        * 3779**2
        * 6299**2
        * 6719**2
        * 9181**2
    ),
    "T2": ZZ(
        5**4
        * 7**3
        * 11**2
        * 13**2
        * 17**2
        * 41**2
        * 43**2
        * 71**2
        * 89**2
        * 127**2
        * 211**2
        * 281**2
        * 503**2
        * 631**2
        * 2309**2
        * 2521**2
        * 2647**2
        * 2729**2
        * 3023**2
        * 3359**2
        * 4409**2
        * 5039**2
        * 19531**2
        * 22679**2
        * 41161**2
    ),
    "window": [ZZ(23)],
    "lambda_security": 128,
}

festa_params_192 = {
    "p": ZZ(
        3989795910464850234544092016437599262156405882930270748007942277640374329764909450701017382298119417718075228827492438972399189797430748073952975120211362411225539619165193856075955921868203757050356678140740906219251807603970371623231282116806721678274928745107855520069582715077651032774292776341154446758673963216798416628169733661537007586004889965092043219442232326309212914425730233888098063333187024715534353168291196289326542828281483050941456739621249443006377886553788444285609603976701383081322473844061620853271098247180307945494907820660461209043068817353444264450905367117823999
    ),
    "l": ZZ(2),
    "b": ZZ(992),
    "f": ZZ(391),
    "d1": ZZ(
        3**5
        * 5**3
        * 19**2
        * 23**2
        * 29**2
        * 43**2
        * 89**2
        * 199**2
        * 271**2
        * 331**2
        * 359**2
        * 991**2
        * 2969**2
        * 3499**2
        * 4951**2
        * 33331**2
        * 63361**2
        * 64679**2
        * 94709**2
        * 176549**2
    ),
    "d2": ZZ(
        11**4
        * 59**2
        * 61**2
        * 71**2
        * 131**2
        * 179**2
        * 659**2
        * 661**2
        * 719**2
        * 1319**2
        * 1321**2
        * 1451**2
        * 1979**2
        * 5939**2
        * 7919**2
        * 17159**2
        * 19139**2
        * 25741**2
        * 47521**2
    ),
    "dA": ZZ(
        31**2
        * 181**2
        * 62701**2
        * 144539**2
        * 424709**2
        * 863279**2
        * 1122659**2
        * 3383819**2
        * 5060551**2
        * 5425201**2
        * 6842881**2
    ),
    "dA1": ZZ(31**2 * 424709**2 * 863279**2 * 5060551**2 * 6842881**2),
    "dA2": ZZ(
        181**2 * 62701**2 * 144539**2 * 1122659**2 * 3383819**2 * 5425201**2
    ),
    "m1": ZZ(68632582800772697337636634005251085750364789754838863495661967589),
    "m2": ZZ(156144937885058024768230728745879148341804830103117312533061),
    "T1": ZZ(
        3**5
        * 5**3
        * 19**2
        * 23**2
        * 29**2
        * 31**2
        * 43**2
        * 89**2
        * 199**2
        * 271**2
        * 331**2
        * 359**2
        * 991**2
        * 2969**2
        * 3499**2
        * 4951**2
        * 33331**2
        * 63361**2
        * 64679**2
        * 94709**2
        * 176549**2
        * 424709**2
        * 863279**2
        * 5060551**2
        * 6842881**2
    ),
    "T2": ZZ(
        11**4
        * 59**2
        * 61**2
        * 71**2
        * 131**2
        * 179**2
        * 181**2
        * 659**2
        * 661**2
        * 719**2
        * 1319**2
        * 1321**2
        * 1451**2
        * 1979**2
        * 5939**2
        * 7919**2
        * 17159**2
        * 19139**2
        * 25741**2
        * 47521**2
        * 62701**2
        * 144539**2
        * 1122659**2
        * 3383819**2
        * 5425201**2
    ),
    "window": [32],
    "lambda_security": 192,
}

festa_params_256 = {
    "p": ZZ(
        2524236426131908174758983473066400852812346764562432280873418011076868935429515561787341249839749101821531343416518767100882381187648733262063632334006428519061426786160065344606367778532280118600960770106523109805661583586342037711423522060390549493563409080501152971986458724994433250257293726521546929353864097227690517811809280660572088683642070309150921837210120829861281018804835762408713046825658101975922164225088949187234629425416074001202829330403462644421027774042354172765841554654727829352824231867022314884687126250586574149213765666745625778080021960028630577931394035300886195838551496562102094274108925887792615514573783252404196605895266664615491280273891146653896461330600686147199611644805132818427258731207422819092912082164021325320819954565051552854993796413035416690643574143829438406091115086135037169500159999
    ),
    "l": ZZ(2),
    "b": ZZ(1472),
    "f": ZZ(137),
    "d1": ZZ(
        5**4
        * 7**5
        * 11**2
        * 13**2
        * 41**2
        * 43**2
        * 71**2
        * 89**2
        * 97**2
        * 211**2
        * 281**2
        * 293**2
        * 491**2
        * 881**2
        * 1471**2
        * 1567**2
        * 2309**2
        * 3359**2
        * 3529**2
        * 3919**2
        * 6763**2
        * 23813**2
        * 41161**2
        * 116423**2
        * 366029**2
        * 513031**2
    ),
    "d2": ZZ(
        3**4
        * 19**2
        * 29**2
        * 59**2
        * 83**2
        * 139**2
        * 167**2
        * 197**2
        * 419**2
        * 421**2
        * 587**2
        * 701**2
        * 839**2
        * 2351**2
        * 2939**2
        * 4507**2
        * 5879**2
        * 5881**2
        * 6719**2
        * 8821**2
        * 16267**2
        * 35279**2
        * 44101**2
        * 182279**2
        * 367501**2
    ),
    "dA": ZZ(
        2729**2
        * 450799**2
        * 525671**2
        * 572321**2
        * 798503**2
        * 921199**2
        * 1635619**2
        * 1644439**2
        * 1685207**2
        * 3103171**2
        * 8239349**2
        * 10202681**2
        * 44988859**2
    ),
    "dA1": ZZ(2729**2 * 3103171**2 * 8239349**2 * 10202681**2),
    "dA2": ZZ(
        450799**2
        * 525671**2
        * 572321**2
        * 798503**2
        * 921199**2
        * 1635619**2
        * 1644439**2
        * 1685207**2
        * 44988859**2
    ),
    "m1": ZZ(
        1042357266661128866919331201762169381931947156600825975104482270992964015290058684511178087865553374285516551084291619229
    ),
    "m2": ZZ(
        23335446570047301884025567277297897484419344685255776773770674345940909378916776121936521
    ),
    "T1": ZZ(
        5**4
        * 7**5
        * 11**2
        * 13**2
        * 41**2
        * 43**2
        * 71**2
        * 89**2
        * 97**2
        * 211**2
        * 281**2
        * 293**2
        * 491**2
        * 881**2
        * 1471**2
        * 1567**2
        * 2309**2
        * 2729**2
        * 3359**2
        * 3529**2
        * 3919**2
        * 6763**2
        * 23813**2
        * 41161**2
        * 116423**2
        * 366029**2
        * 513031**2
        * 3103171**2
        * 8239349**2
        * 10202681**2
    ),
    "T2": ZZ(
        3**4
        * 19**2
        * 29**2
        * 59**2
        * 83**2
        * 139**2
        * 167**2
        * 197**2
        * 419**2
        * 421**2
        * 587**2
        * 701**2
        * 839**2
        * 2351**2
        * 2939**2
        * 4507**2
        * 5879**2
        * 5881**2
        * 6719**2
        * 8821**2
        * 16267**2
        * 35279**2
        * 44101**2
        * 182279**2
        * 367501**2
        * 450799**2
        * 525671**2
        * 572321**2
        * 798503**2
        * 921199**2
        * 1635619**2
        * 1644439**2
        * 1685207**2
        * 44988859**2
    ),
    "window": [ZZ(23)],  # TODO
    "lambda_security": 256,
}

parameter_sets = {
    "FESTA_TOY": festa_params_toy,
    "FESTA_128": festa_params_128,
    "FESTA_192": festa_params_192,
    "FESTA_256": festa_params_256,
}
