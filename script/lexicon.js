const searchInput = document.getElementById('searchInput');
const searchResultsContainer = document.getElementById('searchResultsContainer');
const cardHeading = document.getElementById('cardHeading');
const cardPara = document.getElementById('cardPara');
const cardExtra = document.getElementById('cardExtra');
const cardTag = document.getElementById('cardTag');

// Sample data
const headingsData = [
{
    heading: 'Armageddon',
    para: 'Armageddon is a term that refers to a catastrophic and apocalyptic event or conflict of immense proportions, often associated with the end of the world or a major showdown between opposing forces.',
    extra: 'In religious contexts, Armageddon is mentioned as a final battle between good and evil in some belief systems, particularly in Christian theology.',
    tag: ['#Apocalypse', '#End Times', '#Eschatology']
},
{
    heading: 'Reparation',
    para: 'Reparation refers to the act of making amends, compensating, or providing restitution for harm, damage, or wrongdoing. Reparations can take various forms, including financial compensation, apologies, or efforts to rectify historical injustices.',
    extra: 'Reparation is often discussed in the context of addressing historical injustices, such as slavery, colonization, and human rights abuses. It aims to achieve justice and reconciliation.',
    tag: ['#Compensation', '#Justice', '#Restitution']
},
{
    heading: 'Ration',
    para: 'A ration is a specific portion or allowance of food, supplies, or resources allocated to individuals or groups, often in a controlled or limited manner. Rationing is commonly employed during times of scarcity, emergencies, or in military contexts.',
    extra: 'Rationing aims to ensure equitable distribution and prevent hoarding of essential goods. It has been used in wartime, economic crises, and disaster relief efforts.',
    tag: ['#Allocation', '#Distribution', '#Scarcity']
},
{
    heading: 'Reservoir',
    para: 'A reservoir is a man-made or natural storage area for water, typically formed by constructing dams across rivers or streams. Reservoirs are used to store and manage water for various purposes, including drinking water supply, irrigation, and hydroelectric power generation.',
    extra: 'Reservoirs play a crucial role in water resource management, providing a reliable source of freshwater for communities and industries. They can also have ecological and recreational value.',
    tag: ['#WaterStorage', '#ResourceManagement', '#Hydroelectricity']
},
{
    heading: 'Fort',
    para: 'A fort, short for fortress, is a fortified military structure or building designed to defend against attacks and provide protection to its occupants. Forts have been used throughout history for strategic defense.',
    extra: 'Fortifications can vary in size and complexity, from small outposts to massive citadels. They often include walls, towers, and defensive features.',
    tag: ['#Military', '#Defense', '#Fortification']
},
{
    heading: 'Starve',
    para: 'To starve means to suffer from lack of food and proper nourishment, leading to extreme hunger and malnutrition. It is a condition that can have severe physical and emotional effects on individuals.',
    extra: 'Starvation is a critical global issue, and efforts to combat it include food aid, poverty alleviation, and improved access to nutrition. It is a humanitarian concern that requires attention and action.',
    tag: ['#Hunger', '#Malnutrition', '#Humanitarian']
},
{
    heading: "Century",
    para: "A century is a period of 100 years. It is commonly used as a unit of time to measure historical events, eras, and the passage of time. Centuries are often designated by ordinal numbers, such as the 20th century.",
    extra: "The division of history into centuries helps organize and study different time periods and their cultural, technological, and social developments.",
    tag: ["#Time", "#History", "#Era"]
},
{
    heading: "Mystery",
    para: "A mystery refers to something that is difficult to understand, explain, or solve. It often involves enigmatic or unexplained events, phenomena, or circumstances that arouse curiosity and intrigue.",
    extra: "Mysteries are a common theme in literature, detective stories, and the realm of the unknown. They can spark the human desire to explore and uncover hidden truths.",
    tag: ["#Enigma", "#Intrigue", "#Curiosity"]
},
{
    heading: "Flay",
    para: "To flay means to strip the skin from a person or animal, typically as a form of punishment, torture, or to prepare the body for various purposes. Flaying has been practiced in various cultures throughout history.",
    extra: "Flaying is often associated with brutality and cruelty and has been depicted in art, mythology, and historical accounts. It serves different symbolic and practical functions in different contexts.",
    tag: ["#Punishment", "#Torture", "#Cultural Practices"]
},
{
    heading: "Magic",
    para: "Magic is the practice of using supernatural or mystical forces to influence events, outcomes, or perceptions. It is often associated with rituals, spells, and the manipulation of energy or elements.",
    extra: "Magic has a long history and is found in various forms across cultures and traditions. It can be used for entertainment, religious ceremonies, healing, and other purposes.",
    tag: ["#Supernatural", "#Rituals", "#Mysticism"]
},
{
    heading: "Botanical",
    para: "Botanical relates to the study of plants, their biology, classification, and ecology. It encompasses various scientific disciplines focused on plant life, including botany.",
    extra: "Botanical research contributes to our understanding of plant diversity, conservation, and their role in ecosystems. It has practical applications in agriculture, medicine, and environmental science.",
    tag: ["#Plants", "#Science", "#Biology"]
},
{
    heading: "Botany",
    para: "Botany is a branch of biology that focuses on the scientific study of plants, including their classification, structure, physiology, and interactions with the environment.",
    extra: "Botany plays a critical role in understanding plant life and its significance to human and ecological systems. It has applications in agriculture, horticulture, pharmacology, and more.",
    tag: ["#Science", "#Plants", "#Biology"]
},
{
    heading: "Library",
    para: "A library is a collection of books, documents, and other resources stored for reading, research, and reference purposes. Libraries are often public or academic institutions that provide access to knowledge and information.",
    extra: "Libraries have been essential centers of learning and culture throughout history. In the digital age, they have evolved to include digital resources and services.",
    tag: ["#Books", "#Knowledge", "#Learning"]
},
{
    heading: "Army",
    para: "An army is a large organized military force typically trained and equipped for warfare. Armies are key components of a country's defense and security infrastructure.",
    extra: "The size, capabilities, and organization of armies vary between nations, and they play a crucial role in national defense, peacekeeping missions, and disaster response.",
    tag: ["#Military", "#Defense", "#Warfare"]
},
{
    heading: "Maritime",
    para: "Maritime refers to anything related to the sea, oceans, or navigation on water. It encompasses activities such as shipping, fishing, trade, and exploration conducted on or near bodies of water.",
    extra: "Maritime industries are vital for global trade and transportation. Understanding maritime law and navigation is essential for safe and efficient sea operations.",
    tag: ["#Sea", "#Navigation", "#Trade"]
},
{
    heading: "Sea",
    para: "The sea is a large body of saltwater that covers much of the Earth's surface. It plays a fundamental role in the planet's climate, ecosystems, and human activities, including transportation and trade.",
    extra: "Seas are home to diverse marine life and serve as a source of food, recreation, and inspiration. They also pose challenges such as pollution and conservation.",
    tag: ["#Ocean", "#Water", "#Ecosystem"]
},
{
    heading: "Cargo",
    para: "Cargo refers to goods, products, or materials transported by ships, aircraft, trucks, or other means of transportation. Cargo can include a wide range of items, from raw materials to finished products.",
    extra: "The efficient handling and transportation of cargo are crucial for global trade and the economy. Cargo logistics involve processes such as loading, unloading, and warehousing.",
    tag: ["#Goods", "#Transportation", "#Logistics"]
},
{
    heading: "Goods",
    para: "Goods are tangible products or commodities that can be bought, sold, or traded. They are typically manufactured or produced for consumption, use, or resale.",
    extra: "Goods encompass a wide range of items, from everyday consumer products to industrial machinery. They are a fundamental part of economic systems and trade.",
    tag: ["#Products", "#Commerce", "#Trade"]
},
{
    heading: "Sail",
    para: "To sail means to navigate a watercraft, such as a sailboat, by harnessing the wind's power using sails. Sailing is a popular recreational activity and an ancient method of transportation and exploration.",
    extra: "Sailing involves a combination of skills, including sail handling, navigation, and understanding wind patterns. It has a rich history and continues to be a beloved pastime.",
    tag: ["#Boating", "#Navigation", "#Recreation"]
},
{
    heading: "Oar",
    para: "An oar is a long pole with a flat blade used for rowing or propelling a boat through the water. Oars are essential tools for manual navigation and propulsion of watercraft.",
    extra: "Rowing with oars requires physical effort and coordination. Oars are commonly used in rowboats, canoes, and other small watercraft.",
    tag: ["#Rowing", "#Boating", "#Watercraft"]
},
{
    heading: "Skeleton",
    para: "A skeleton is the internal framework of bones that provides structure, support, and protection to the bodies of vertebrate animals, including humans. It also serves as an anchor for muscles and tissues.",
    extra: "The study of skeletons, known as osteology, contributes to our understanding of anatomy, evolution, and forensics. Skeletons are essential for mobility and bodily functions.",
    tag: ["#Anatomy", "#Bones", "#Structure"]
},
{
    heading: "Iron",
    para: "Iron is a chemical element with the symbol Fe and atomic number 26. It is one of the most abundant elements on Earth and has a wide range of uses, including in construction, manufacturing, and metallurgy.",
    extra: "Iron is known for its strength and versatility. It is essential for the production of steel, a crucial material in infrastructure and industrial applications.",
    tag: ["#Element", "#Metallurgy", "#Construction"]
},
{
    heading: "Copper",
    para: "Copper is a chemical element with the symbol Cu and atomic number 29. It is a ductile metal known for its excellent electrical and thermal conductivity, making it valuable in various industries.",
    extra: "Copper is used in electrical wiring, plumbing, architecture, and as a component in alloys. Its antimicrobial properties also make it useful in healthcare applications.",
    tag: ["#Element", "#Conductivity", "#Metals"]
},
{
    heading: "Wood",
    para: "Wood is a natural material derived from the trunks, branches, and roots of trees and woody plants. It is known for its versatility and has been used by humans for construction, furniture, and various applications for centuries.",
    extra: "Woodworking is a craft that involves shaping and working with wood to create functional and decorative objects. Sustainable forestry practices are important for wood conservation.",
    tag: ["#Material", "#Craftsmanship", "#Sustainability"]
},
{
    heading: "Technology",
    para: "Technology refers to the application of scientific knowledge, tools, and techniques to solve problems, achieve goals, or improve processes. It encompasses a wide range of innovations and advancements across various fields.",
    extra: "Technology has transformed nearly every aspect of human life, from communication and transportation to healthcare and entertainment. It continues to evolve rapidly.",
    tag: ["#Innovation", "#Science", "#Advancement"]
},
{
    heading: "Cruse",
    para: "A cruse is a small container, typically made of pottery, ceramic, or other materials, used for holding liquids such as oil, wine, or other substances. Cruses have been used for storage and serving purposes throughout history.",
    extra: "Cruses often have cultural or symbolic significance in religious and historical contexts. They come in various shapes and sizes.",
    tag: ["#Container", "#Vessel", "#Storage"]
},
{
    heading: "Ship",
    para: "A ship is a large watercraft designed for navigation on seas, oceans, or other bodies of water. Ships come in various types, including cargo ships, passenger ships, warships, and more.",
    extra: "Ships have played a pivotal role in human history, enabling trade, exploration, and military campaigns. They are essential for global transportation and maritime industries.",
    tag: ["#Vessel", "#Navigation", "#Maritime"]
},
{
    heading: "Boat",
    para: "A boat is a small watercraft designed for personal or small-group transportation on water. Boats are typically smaller than ships and come in various forms, including rowboats, sailboats, and motorboats.",
    extra: "Boating is a popular recreational activity, and boats are used for fishing, water sports, and leisurely cruises. They are versatile and accessible vessels.",
    tag: ["#Watercraft", "#Recreation", "#Transportation"]
},
{
    heading: "Concept",
    para: "A concept is an abstract idea, notion, or thought that represents something mentally conceived or imagined. Concepts are fundamental to human cognition and communication, serving as building blocks for knowledge and understanding.",
    extra: "Concepts can range from simple to complex and play a crucial role in various fields, including philosophy, science, and education.",
    tag: ["#Ideas", "#Cognition", "#Understanding"]
},
{
    heading: "Light",
    para: "Light is electromagnetic radiation that is visible to the human eye. It is a form of energy that travels in waves and illuminates the world around us.",
    extra: "Light has both practical and scientific significance, serving as a source of illumination, a tool for communication, and a subject of study in optics and physics.",
    tag: ["#Radiation", "#Illumination", "#Physics"]
},
{
    heading: "Chieftain",
    para: "A chieftain is a tribal or clan leader who holds authority and leadership within a community or group. Chieftains often play significant roles in decision-making, governance, and conflict resolution.",
    extra: "Chieftains can be found in various cultures and historical contexts, including indigenous societies and early human civilizations.",
    tag: ["#Leadership", "#Tribal", "#Authority"]
},
{
    heading: "Resource",
    para: "A resource is a source of supply, support, or aid that can be used to meet a need or achieve a goal. Resources can be natural, human-made, or intangible and are essential for sustenance, development, and progress.",
    extra: "Effective resource management is crucial for sustainability and responsible use of available assets. Resources can include materials, knowledge, energy, and more.",
    tag: ["#Supply", "#Sustainability", "#Management"]
},
{
    heading: "Advantage",
    para: "An advantage is a favorable or beneficial circumstance or condition that provides an edge or superiority in a specific situation. Advantages can be strategic, competitive, or situational.",
    extra: "Gaining and leveraging advantages are common goals in various contexts, such as business, sports, and military strategy. They contribute to success and achievement.",
    tag: ["#Benefit", "#Superiority", "#Strategy"]
},
{
    heading: "Decentralize",
    para: "To decentralize means to distribute power, authority, or decision-making to multiple smaller units or entities, rather than centralizing it in a single, central authority. Decentralization is often seen as a way to promote autonomy and local control.",
    extra: "Decentralization can be applied in governance, organizations, and technology systems. It aims to improve efficiency, flexibility, and responsiveness.",
    tag: ["#Power Distribution", "#Autonomy", "#Decision-Making"]
},
{
    heading: "Sail",
    para: "To sail means to navigate a watercraft, such as a sailboat, by harnessing the wind's power using sails. Sailing is a popular recreational activity and an ancient method of transportation and exploration.",
    extra: "Sailing involves a combination of skills, including sail handling, navigation, and understanding wind patterns. It has a rich history and continues to be a beloved pastime.",
    tag: ["#Boating", "#Navigation", "#Recreation"]
},
{
    heading: "Field",
    para: "A field is an open area or expanse of land, often used for agricultural purposes, sports, research, or various activities. Fields can be natural or human-made and serve diverse functions.",
    extra: "Fields can be found in rural and urban settings and have cultural and practical significance. They provide space for farming, sports, scientific experiments, and more.",
    tag: ["#Land", "#Agriculture", "#Recreation"]
},
{
    heading: "Play",
    para: "Play is a voluntary and recreational activity engaged in for enjoyment, amusement, and fun. It is often characterized by imagination, creativity, and a lack of strict rules or goals.",
    extra: "Play is essential for the development of children and contributes to well-being and social bonding in people of all ages. It encompasses various forms, from games to creative play.",
    tag: ["#Recreation", "#Fun", "#Creativity"]
},
{
    heading: "Vigorous",
    para: "Vigorous describes something that is full of physical strength, energy, and intensity. It implies robustness, forcefulness, and an active and lively quality.",
    extra: "Vigorous activities can include exercise, sports, or any strenuous and dynamic efforts. The term is often associated with vitality and enthusiasm.",
    tag: ["#Strength", "#Energy", "#Intensity"]
},
{
    heading: "Prosper",
    para: "To prosper means to achieve success, wealth, and well-being. Prosperity often implies economic and personal growth, as well as an overall improvement in one's circumstances.",
    extra: "Prosperity can be pursued through various means, including business endeavors, education, and personal development. It is a common aspiration for individuals and societies.",
    tag: ["#Success", "#Wealth", "#Well-Being"]
},
{
    heading: "Longship",
    para: "A longship is a type of specialized naval vessel used by the ancient Norse peoples, particularly the Vikings, for exploration, trade, and warfare. Longships were characterized by their long and narrow design, which made them highly maneuverable.",
    extra: "Longships played a significant role in Viking history and allowed them to navigate rivers, coastal waters, and open seas. They were essential for raiding and exploration in the medieval era.",
    tag: ["#Norse", "#Viking", "#Naval Vessel"]
},
{
    heading: "River",
    para: "A river is a natural watercourse that flows towards an ocean, sea, lake, or another river. Rivers are vital for the Earth's hydrological cycle and serve as sources of freshwater, transportation routes, and habitats for diverse ecosystems.",
    extra: "Rivers have played a central role in human history, providing water for agriculture, trade routes, and settlements. They hold cultural and ecological significance.",
    tag: ["#Watercourse", "#Freshwater", "#Ecosystem"]
},
{
    heading: "Economy",
    para: "An economy refers to the system of production, distribution, and consumption of goods and services within a region or country. Economies are shaped by various factors, including government policies, market forces, and cultural influences.",
    extra: "Economies can be categorized into different types, such as market economies, command economies, and mixed economies. They are central to the well-being and development of societies.",
    tag: ["#Production", "#Consumption", "#Economic Systems"]
},
{
    heading: "Governance",
    para: "Governance refers to the process and system by which a group, organization, or entity is managed, directed, and controlled. It encompasses the decisions, policies, and actions that shape the direction and functioning of a governing body or institution.",
    extra: "Effective governance is essential in various sectors, including government, business, and non-profit organizations, as it influences decision-making, accountability, and overall performance.",
    tag: ["#Management", "#Leadership", "#Decision-Making"]
},
{
    heading: "Government",
    para: "Government is a structured system and body responsible for making and enforcing laws, policies, and regulations within a defined territory or jurisdiction. Governments are essential for maintaining order, providing public services, and representing the interests of citizens.",
    extra: "Forms of government can vary, including democracies, monarchies, republics, and authoritarian regimes, each with its own principles of governance and leadership.",
    tag: ["#Politics", "#Administration", "#Jurisdiction"]
},
{
    heading: "Unwind",
    para: "To unwind means to relax, de-stress, or ease tension and pressure. It involves taking a break or engaging in activities that promote a sense of calm and well-being, often after a period of work or stress.",
    extra: "Unwinding can take various forms, such as leisurely activities, meditation, or spending time in nature. It is important for mental and emotional health.",
    tag: ["#Relaxation", "#Stress Relief", "#Well-Being"]
},
{
    heading: "Anxious",
    para: "Anxious is an adjective used to describe a state of unease, worry, or nervousness. It is often associated with apprehension about future events or situations and can manifest as physical and emotional symptoms.",
    extra: "Anxiety is a common human experience, and individuals may use various coping strategies, such as mindfulness and therapy, to manage and reduce anxious feelings.",
    tag: ["#Emotions", "#Mental Health", "#Stress"]
},
{
    heading: "Anglo-Saxons",
    para: "The Anglo-Saxons were a group of Germanic tribes who settled in England during the early Middle Ages, following the decline of the Roman Empire. They played a significant role in shaping the culture, language, and history of England.",
    extra: "The Anglo-Saxon period is known for its literature, including epic poems like Beowulf, and the eventual establishment of the Kingdom of England. It had a lasting impact on the English identity.",
    tag: ["#History", "#Culture", "#Middle Ages"]
},
{
    heading: "Castle",
    para: "A castle is a fortified structure or building, often with a moat and defensive walls, designed for protection and as a residence for nobility or royalty. Castles were prevalent in medieval Europe and served as symbols of power and authority.",
    extra: "Castles featured various architectural elements, including battlements, drawbridges, and towers, and played key roles in military strategies and the feudal system.",
    tag: ["#Architecture", "#History", "#Fortification"]
},
{
    heading: "Stronghold",
    para: "A stronghold is a highly fortified and secure place, typically used for defense during a conflict or as a base of operations. Strongholds are strategically located and equipped to withstand attacks and sieges.",
    extra: "In history, strongholds were essential in military campaigns and were often situated in key geographic locations to control territory and resources.",
    tag: ["#Fortification", "#Defense", "#Military"]
},
{
    heading: "Hispanic",
    para: "Hispanic is a term used to describe people and cultures with a historical connection to Spain or Spanish-speaking countries. It often includes individuals from Latin America, Spain, and other Spanish-speaking regions.",
    extra: "Hispanic identity is diverse and encompasses a wide range of languages, traditions, and backgrounds. It is an important aspect of multicultural societies.",
    tag: ["#Culture", "#Identity", "#Diversity"]
},
{
    heading: "Euro-Asian",
    para: "Euro-Asian, also known as Eurasian, refers to the vast landmass that combines Europe and Asia. It is the world's largest contiguous landmass and encompasses a wide range of geographical, cultural, and historical diversity.",
    extra: "Eurasia has played a crucial role in human history, as it has been a crossroads for trade, migrations, and the exchange of ideas between East and West.",
    tag: ["#Geography", "#Cultural Diversity", "#History"]
},
{
    heading: "Latin",
    para: "Latin is a classical language that originated in ancient Rome and was widely used in the Roman Empire. It has had a profound influence on the development of Romance languages and is still used in various fields today.",
    extra: "Latin phrases and terminology are commonly found in legal, scientific, and religious contexts. Learning Latin is also a valuable skill for understanding the roots of modern languages.",
    tag: ["#Language", "#Classical", "#Education"]
},
{
    heading: "Exotic",
    para: "Exotic is an adjective used to describe something unusual, foreign, or unfamiliar. It often conveys a sense of intrigue and fascination, as exotic things are different from one's everyday experiences.",
    extra: "Exoticism can apply to various aspects of life, including travel destinations, cuisine, and cultural practices. It adds diversity and richness to the world's cultural tapestry.",
    tag: ["#Unusual", "#Fascination", "#Diversity"]
},
{
    heading: "Aristocrat",
    para: "An aristocrat is a person belonging to the upper social class or nobility, often characterized by inherited wealth, privileges, and prestige. Aristocrats have historically held significant influence in society and politics.",
    extra: "Aristocracy is a social hierarchy in which power and authority are concentrated among the aristocratic elite. It has been a central feature of many historical societies.",
    tag: ["#Social Class", "#Privilege", "#Nobility"]
},
{
    heading: "Strategy",
    para: "Strategy refers to a well-thought-out plan or approach designed to achieve specific goals or objectives. It involves careful consideration of resources, tactics, and potential outcomes.",
    extra: "Strategic thinking is important in various fields, including business, military, and sports. Effective strategies can lead to success and competitive advantage.",
    tag: ["#Planning", "#Tactics", "#Goals"]
},
{
    heading: "Reign",
    para: "A reign refers to the period during which a monarch holds and exercises authority, often as the head of a monarchy. It encompasses the entirety of a monarch's rule, from the moment they ascend to the throne until their abdication, death, or removal from power.",
    extra: "Reigns can vary significantly in length and impact, from short and uneventful ones to long and influential eras that leave a lasting mark on a nation's history. They are central to the concept of monarchy, where a single individual, known as a monarch, holds supreme authority over a realm or state.",
    tag: ["#Monarchy", "#Authority", "#Rule"]
},
{
    heading: "Sovereign",
    para: "A sovereign is a term used to describe a ruler or leader who possesses supreme authority and control over a specific territory, nation, or state. Sovereigns have the highest legal and political power and are not subject to the authority of another ruler.",
    extra: "Sovereignty is a fundamental concept in political science and international law, representing the independence and self-governance of a nation. It involves the ability to make laws, engage in foreign relations, and exercise power within one's borders.",
    tag: ["#Leadership", "#Authority", "#Independence"]
},
{
    heading: "Monarchy",
    para: "Monarchy is a system of government in which a single individual, often referred to as a monarch, holds supreme authority and serves as the head of state. Monarchies can be hereditary, where leadership passes within a royal family, or elective, where a monarch is chosen by other means.",
    extra: "Monarchies have existed in various forms throughout history and can range from absolute monarchies with unlimited power to constitutional monarchies, where the monarch's authority is limited by a constitution or laws.",
    tag: ["#Government", "#Leadership", "#Royal"]
},
{
    heading: "Monarch",
    para: "A monarch is an individual who holds the highest position of authority and leadership within a monarchy. Monarchs can be kings, queens, emperors, or other titles, depending on the specific cultural or historical context.",
    extra: "The role and powers of a monarch can vary widely between different monarchies and historical periods. Some monarchs have held absolute power, while others have been figureheads with limited authority.",
    tag: ["#Leadership", "#Authority", "#Royalty"]
},
{
    heading: 'Dialect',
    para: 'A dialect is a specific form of a language spoken by a particular group of people or in a specific region. It encompasses variations in pronunciation, vocabulary, grammar, and sometimes even sentence structure.',
    extra: 'Dialects can emerge due to geographic isolation, cultural factors, historical influences, or social distinctions. They are often characterized by unique linguistic features and expressions.',
    tag: ['#Language Variation', '#Regional Speech', '#Cultural Influence']
},
{
    heading: 'Exodus',
    para: 'An exodus refers to a mass departure or migration of a large group of people from one place to another, often due to political, social, or environmental factors. It can involve the relocation of a population from a specific region or country.',
    extra: 'The term "exodus" is frequently associated with historical events, such as the biblical Exodus of the Israelites from Egypt. Exodus can result from factors like conflict, persecution, natural disasters, or economic conditions.',
    tag: ['#Migration', '#Mass Departure', '#Relocation']
},
{
    heading: 'Voyage',
    para: 'A voyage is a journey or expedition, typically by sea or through unknown or distant regions. It often implies travel over a considerable distance, and it can be for various purposes, such as exploration, trade, or adventure.',
    extra: 'Voyages have played a significant role in human history, including the Age of Exploration when explorers embarked on voyages to discover new lands and trade routes. Voyages can also be undertaken for leisure and cultural exchange.',
    tag: ['#Journey', '#Sea Travel', '#Exploration']
},
{
    heading: 'Aqueduct',
    para: 'An aqueduct is a man-made structure or system designed to transport water, often over long distances, from one location to another. It is used to supply water for various purposes, including drinking, irrigation, and industrial use.',
    extra: 'Aqueducts can take various forms, including open channels, elevated bridges, and underground tunnels, depending on the terrain and engineering requirements. They have been used by ancient civilizations and are still employed in modern water supply systems.',
    tag: ['#Water Transport', '#Infrastructure', '#Water Supply']
},
{
    heading: 'Colosseum',
    para: 'The Colosseum, also known as the Flavian Amphitheatre, is an ancient Roman amphitheater located in Rome, Italy. It is one of the most iconic and well-preserved ancient structures in the world.',
    extra: 'The Colosseum was used for various forms of entertainment, including gladiator contests and public spectacles. It could hold tens of thousands of spectators and is a symbol of Roman engineering and culture.',
    tag: ['#Ancient Rome', '#Amphitheater', '#Historical Landmark']
},
{
    heading: 'Indenture',
    para: 'Indenture is a legal contract or agreement between two or more parties, often in a written document with indented edges (hence the name). It typically outlines specific terms, conditions, or obligations to be fulfilled.',
    extra: 'Indentures have historically been used for various purposes, including apprenticeship agreements, land transactions, and labor contracts. They often involve a binding commitment or obligation.',
    tag: ['#Contract', '#Agreement', '#Legal Document']
},
{
    heading: 'Delicacy',
    para: 'Delicacy has multiple meanings, but it often refers to something rare, exquisite, or considered a luxury, especially in the context of food. Delicacies are often highly prized for their unique flavors and qualities.',
    extra: 'Delicacies can include foods like caviar, truffles, or rare seafood. The term can also be used more broadly to describe anything of great value, fragility, or sensitivity.',
    tag: ['#Exquisite', '#Luxury', '#Rare']
},
{
    heading: 'Ailments',
    para: 'Ailments are physical or mental health conditions or illnesses that cause discomfort, distress, or impairment of normal functioning. They can range from minor illnesses to more serious medical conditions.',
    extra: 'Ailments may include symptoms like fever, pain, fatigue, or psychological distress. The term is commonly used to refer to health issues that require medical attention or treatment.',
    tag: ['#Health Conditions', '#Illness', '#Medical Treatment']
},
{
    heading: 'Savage',
    para: 'Savage is an adjective used to describe behavior or actions that are extremely brutal, violent, or uncivilized. It implies a lack of restraint and adherence to social norms.',
    extra: 'The term "savage" has been historically used in colonial and ethnocentric contexts to label indigenous or non-Western cultures as uncivilized. Its usage has been criticized as derogatory and biased.',
    tag: ['#Brutal', '#Uncivilized', '#Ethnocentrism']
},
{
    heading: 'Atrocity',
    para: 'An atrocity is an extremely cruel, brutal, or heinous act or event that causes great suffering, harm, or outrage. It often involves actions that violate moral or ethical standards.',
    extra: 'Atrocities can take various forms, including acts of violence, mass killings, and human rights abuses. They are considered grave violations of humanitarian and ethical norms.',
    tag: ['#Cruelty', '#Harm', '#Human Rights']
},
{
    heading: 'Moat',
    para: 'A moat is a deep, wide ditch or trench that surrounds a castle, fortification, or building. It is typically filled with water and serves as a defensive barrier against attackers.',
    extra: 'Moats were historically used as defensive features to hinder access to a structure and make it more difficult for besieging forces to breach its walls. Today, moats are primarily of historical or aesthetic significance.',
    tag: ['#Defense', '#Castle', '#Fortification']
},
{
    heading: 'Justice',
    para: 'Justice is the principle of fairness, righteousness, and the equitable treatment of individuals within a legal and moral framework. It involves the upholding of rights, the rule of law, and the resolution of disputes.',
    extra: 'Justice encompasses concepts such as due process, accountability, and the protection of human rights. It is often pursued through legal systems and institutions to ensure impartiality and fairness.',
    tag: ['#Fairness', '#Legal System', '#Human Rights']
},
{
    heading: 'Invasion',
    para: 'An invasion is the act of entering and taking control of a foreign territory or region, typically by military force. Invasions are often characterized by the occupation and subjugation of the invaded area.',
    extra: 'Invasions can be motivated by territorial expansion, conquest, or strategic objectives. They have historically been a source of conflict and geopolitical change.',
    tag: ['#Military Action', '#Occupation', '#Territorial Control']
},
{
    heading: 'Slaughter',
    para: 'Slaughter refers to the act of killing animals or humans, often in a brutal or large-scale manner. It is associated with violence and the taking of lives.',
    extra: 'Slaughter can occur for various purposes, including food production, hunting, or acts of violence in conflict. It is a term that conveys the loss of life and is often used in the context of brutality or mass killings.',
    tag: ['#Killing', '#Violence', '#Brutality']
},
{
    heading: 'Clan',
    para: 'A clan is a social group or extended family unit, often with a shared ancestry or common lineage. Clans are typically characterized by close-knit relationships and may have their own traditions and customs.',
    extra: 'Clans have existed in various cultures and regions throughout history, and they can play important roles in social organization and identity. Clan members often support one another and share responsibilities.',
    tag: ['#Social Group', '#Lineage', '#Traditions']
},
{
    heading: 'Strife',
    para: 'Strife refers to conflict, discord, or disagreement, often characterized by intense and hostile disputes or struggles between individuals, groups, or entities.',
    extra: 'Strife can occur in various contexts, including personal relationships, politics, and social dynamics. It can lead to tension, division, and, in some cases, open confrontations.',
    tag: ['#Conflict', '#Disagreement', '#Hostility']
},
{
    heading: 'Destitute',
    para: 'Destitute is an adjective used to describe individuals or groups who are extremely poor and lacking basic necessities, such as food, shelter, and clothing. It implies a state of extreme poverty and deprivation.',
    extra: 'People who are destitute often face significant hardships and challenges in meeting their basic needs. Social welfare programs and charitable efforts may provide assistance to destitute individuals.',
    tag: ['#Poverty', '#Deprivation', '#Hardship']
},
{
    heading: 'Warlord',
    para: 'A warlord is a military leader, often with considerable power and influence, who commands armed forces and may exercise control over a specific region or territory through force and coercion.',
    extra: 'Warlords can emerge in times of conflict or political instability and may govern autonomously, challenging central authorities. Their rule is often characterized by the use of force to maintain control.',
    tag: ['#Military Leader', '#Power', '#Conflict']
},
{
    heading: 'Barbarian',
    para: 'A barbarian is a historical term that originally referred to a person or group perceived as culturally, linguistically, or socially inferior or foreign by the standards of a particular civilization or culture.',
    extra: 'The term "barbarian" has been used in various historical contexts to describe outsiders or non-citizens. It often carried a pejorative or derogatory connotation, implying a lack of refinement or civility.',
    tag: ['#Cultural Perception', '#Outsider', '#Historical Term']
},
{
    heading: 'Imperial',
    para: 'Imperial refers to something related to an empire or the characteristics associated with imperial rule, such as dominance, expansion, and influence over other territories and peoples.',
    extra: 'Imperialism is a historical and political concept where a powerful nation extends its authority and control over other regions. Imperial policies have shaped world history and international relations.',
    tag: ['#Empire', '#Dominance', '#Expansion']
},
{
    heading: 'Exile',
    para: 'Exile is the forced or voluntary absence of an individual or group from their homeland or native country, often due to political, social, or personal reasons. It involves living in a foreign land or place.',
    extra: 'Exile can result from political persecution, conflicts, or personal choices. It can be a challenging experience and may involve a sense of displacement and loss of one\'s familiar environment.',
    tag: ['#Forced Absence', '#Displacement', '#Homeland']
},
{
    heading: 'Nationalism',
    para: 'Nationalism is a political ideology or sentiment characterized by a strong attachment to one\'s nation or country, often involving pride in its culture, history, and identity.',
    extra: 'Nationalism can have both positive and negative manifestations. While it can foster unity and patriotism, it can also lead to conflicts when it becomes extreme or exclusionary.',
    tag: ['#Patriotism', '#National Identity', '#Political Ideology']
},
{
    heading: 'Liberal',
    para: 'Liberal, when used in a political or philosophical context, refers to a broad range of ideas and beliefs that emphasize individual rights, freedoms, and progressive social policies.',
    extra: 'Liberalism is often associated with democratic systems that protect civil liberties, promote social equality, and advocate for government intervention in areas such as education and healthcare.',
    tag: ['#Individual Rights', '#Progressive Policies', '#Social Equality']
},
{
    heading: 'Regime',
    para: 'A regime is a system of government or ruling authority that governs a country or political entity. It encompasses the leadership, policies, and structures that define a government.',
    extra: 'Regimes can be democratic, authoritarian, or of other forms, and they can vary widely in their ideologies and approaches. The term is often used to describe governments, especially those with centralized authority.',
    tag: ['#Government System', '#Leadership', '#Policies']
},
{
    heading: 'Legal',
    para: 'Legal refers to something that is in accordance with the law, regulations, or established rules and norms. It pertains to actions, processes, or matters that are recognized and permissible under the legal system.',
    extra: 'Legal principles and standards are essential for maintaining order, resolving disputes, and upholding justice in societies. Legal matters are often adjudicated in courts of law.',
    tag: ['#Lawful', '#Compliance', '#Legal System']
},
{
    heading: 'Constitution',
    para: 'A constitution is a fundamental set of laws, principles, and rules that establish the framework for governance in a country or organization. It defines the structure of government and the rights and responsibilities of citizens.',
    extra: 'Constitutions can take various forms, including written and unwritten, and may be amended or revised over time. They serve as the supreme legal authority in a given jurisdiction.',
    tag: ['#Fundamental Laws', '#Governance Framework', '#Rights and Responsibilities']
},
{
    heading: 'Coup',
    para: 'A coup, short for coup d\'état, is a sudden and often violent overthrow of a government or ruling authority, typically carried out by a faction within the existing power structure.',
    extra: 'Coups can result in changes of leadership, government, or regime. They are often motivated by political, military, or ideological factors and can lead to significant political upheaval.',
    tag: ['#Overthrow', '#Political Change', '#Regime Change']
},
{
    heading: 'Consulate',
    para: 'A consulate is a diplomatic office or mission established by one country in another, typically in a foreign city, to provide services and assistance to its citizens, facilitate trade, and engage in diplomatic relations.',
    extra: 'Consulates play important roles in international diplomacy and often offer consular services such as visa issuance, passport renewal, and assistance to nationals living abroad.',
    tag: ['#Diplomacy', '#Consular Services', '#International Relations']
},
{
    heading: 'Wise',
    para: 'Wise is an adjective used to describe someone who possesses wisdom, sound judgment, and knowledge gained through experience. It implies the ability to make thoughtful and informed decisions.',
    extra: 'Wise individuals are often respected for their guidance and insights. Wisdom can be acquired over time and is associated with qualities such as prudence and discernment.',
    tag: ['#Wisdom', '#Sound Judgment', '#Knowledge']
},
{
    heading: 'Oligarchy',
    para: 'Oligarchy is a system of government or social structure in which power is concentrated in the hands of a small, privileged, and often wealthy group or elite.',
    extra: 'In an oligarchic system, a few individuals or families exert significant influence over political, economic, and social affairs. Oligarchies can limit access to power and resources for the broader population.',
    tag: ['#Power Concentration', '#Privilege', '#Elite Control']
},
{
    heading: 'Fraternity',
    para: 'Fraternity refers to a group or organization of people who share common interests, goals, or values and often form close bonds of friendship and mutual support. It can also refer to the concept of brotherhood.',
    extra: 'Fraternities are commonly associated with universities and colleges, where they promote camaraderie and social activities among members. The term can also be used more broadly to describe solidarity and unity.',
    tag: ['#Brotherhood', '#Mutual Support', '#Camaraderie']
},
{
    heading: 'Equality',
    para: 'Equality is the principle of fairness and equal treatment for all individuals, regardless of their background, characteristics, or circumstances. It involves the absence of discrimination or bias.',
    extra: 'Equality can pertain to various aspects of life, including gender equality, racial equality, and economic equality. It is often a goal in the pursuit of social justice and human rights.',
    tag: ['#Fairness', '#Non-Discrimination', '#Social Justice']
},
{
    heading: 'Liberty',
    para: 'Liberty, often referred to as freedom, is the state of being free from oppression, restrictions, or external control. It encompasses the ability to make choices and pursue individual rights and interests.',
    extra: 'Liberty is a fundamental value in democracies and societies that prioritize individual rights and civil liberties. It includes freedom of speech, religion, and assembly.',
    tag: ['#Freedom', '#Individual Rights', '#Civil Liberties']
},
{
    heading: 'Extremism',
    para: 'Extremism refers to radical or extreme beliefs, ideologies, or actions that deviate significantly from mainstream or moderate views. It often involves a willingness to use violence or force to advance a cause.',
    extra: 'Extremist ideologies can be political, religious, or ideological and may pose threats to societal stability and security. Combating extremism is a concern for governments and communities.',
    tag: ['#Radicalism', '#Violence', '#Ideology']
},
{
    heading: 'Autocracy',
    para: 'Autocracy is a system of government in which a single individual, often a monarch or dictator, holds absolute and unchecked power, making decisions without the consent of others.',
    extra: 'Autocracies are characterized by the concentration of authority in one person or a small group. They can limit political freedoms and civil liberties, as power is highly centralized.',
    tag: ['#Absolute Power', '#Authoritarianism', '#Centralized Rule']
},
{
    heading: 'Democracy',
    para: 'Democracy is a system of government in which the people have the authority to make decisions through voting, typically in free and fair elections. It emphasizes the participation of citizens in the decision-making process.',
    extra: 'Democracy values individual rights, freedom of expression, and the protection of minority interests. It can take various forms, including direct democracy and representative democracy.',
    tag: ['#Government System', '#Citizen Participation', '#Elections']
},
{
    heading: 'Republic',
    para: 'A republic is a form of government in which the country is considered a "public matter" and political power is held by elected officials, often with a president serving as the head of state.',
    extra: 'Republics emphasize the rule of law, representation of citizens, and the protection of individual rights. They can take various forms, including democratic republics, where leaders are elected by the people.',
    tag: ['#Government', '#Elected Officials', '#Rule of Law']
},
{
    heading: 'Chaos',
    para: 'Chaos refers to a state of complete disorder, confusion, and unpredictability. It is characterized by the absence of organization or control.',
    extra: 'In various contexts, chaos can be a temporary and natural state, such as in chaotic systems in physics and mathematics. However, it is often used to describe situations of turmoil and instability.',
    tag: ['#Disorder', '#Confusion', '#Unpredictability']
},
{
    heading: 'Scepter',
    para: 'A scepter is an ornamental staff or rod, often carried by a monarch or ruler as a symbol of authority and sovereignty. It is typically embellished with decorative elements and can represent the ruler\'s right to rule.',
    extra: 'Scepters have been used in various cultures and historical periods to signify leadership and power. They are often seen in ceremonial and royal contexts, such as coronations and formal events.',
    tag: ['#Symbol of Authority', '#Ceremonial Staff', '#Sovereignty']
},
{
    heading: 'Herald',
    para: 'A herald is a person or official who proclaims important news, announcements, or messages, often in a formal or ceremonial manner. Heralds have historically played roles in conveying royal decrees, news of battles, and other significant events.',
    extra: 'The term "herald" can also refer to a sign or indicator of something to come, and it is often associated with the concept of announcing or heralding a new era or change.',
    tag: ['#Announcement', '#Messenger', '#Proclamation']
},
{
    heading: 'Chronicle',
    para: 'A chronicle is a historical record or narrative that documents events in chronological order. It serves as a written account of significant occurrences, often in the form of a continuous narrative.',
    extra: 'Chronicles are valuable sources for historians and researchers, providing insights into the past, including political developments, social changes, and cultural trends. They can take the form of books, manuscripts, or historical writings.',
    tag: ['#Historical Record', '#Narrative', '#Documentation']
},
{
    heading: 'Recursion',
    para: 'Recursion is a programming and mathematical concept where a function or process calls itself in a repetitive and self-referential manner. It is often used to solve problems that can be broken down into smaller, similar sub-problems.',
    extra: 'Recursion is a fundamental technique in computer science and mathematics and is employed in algorithms, data structures, and problem-solving. It allows for elegant and concise solutions to complex problems.',
    tag: ['#Programming', '#Mathematics', '#Problem-Solving']
},
{
    heading: 'Extravagant',
    para: 'Extravagant is an adjective used to describe something that is excessive, lavish, or opulent in nature. It implies a lack of restraint or a willingness to spend or display extravagance.',
    extra: 'Extravagant lifestyles, spending, or events are often associated with luxury and a desire for conspicuous consumption. The term can be applied to various aspects of life, such as fashion, celebrations, or purchases.',
    tag: ['#Lavish', '#Opulence', '#Excess']
},
{
    heading: 'Trade',
    para: 'Trade is the exchange of goods, services, or commodities between individuals, groups, or nations. It is a fundamental economic activity that facilitates the distribution of products and resources.',
    extra: 'Trade can occur at local, national, or international levels and plays a central role in economic development and globalization. It involves buying, selling, and bartering various goods and services.',
    tag: ['#Exchange', '#Commerce', '#Economic Activity']
},
{
    heading: 'Annex',
    para: 'To annex means to incorporate or attach a territory, region, or political entity into another, often larger, one. Annexation typically involves the extension of sovereignty and control over the annexed area.',
    extra: 'Annexations can occur through political agreements, treaties, or military actions. They have been historically employed by nations to expand their territories or assert dominance.',
    tag: ['#Incorporation', '#Territorial Expansion', '#Sovereignty']
},
{
    heading: 'Realm',
    para: 'A realm is a territory, domain, or sphere of influence ruled or governed by a particular authority, such as a monarch or government. It represents a distinct and often defined area or jurisdiction.',
    extra: 'Realms can refer to physical territories, but they can also extend to metaphorical or conceptual domains, such as the realm of ideas or the realm of politics. The term conveys the idea of control or sovereignty.',
    tag: ['#Territory', '#Jurisdiction', '#Sphere of Influence']
},
{
    heading: 'Famine',
    para: 'Famine is a severe and widespread scarcity of food, resulting in hunger, malnutrition, and sometimes starvation. Famines are typically caused by factors such as crop failure, food shortages, or political and environmental crises.',
    extra: 'Famines have historically led to devastating consequences for affected populations, including loss of life and long-term health problems. They often require humanitarian efforts to alleviate suffering.',
    tag: ['#Food Scarcity', '#Hunger', '#Humanitarian Crisis']
},
{
    heading: 'Legacy',
    para: 'Legacy refers to the lasting impact, influence, or contributions that an individual, organization, or event leaves behind. It often encompasses the positive or significant aspects of a person\'s life or work.',
    extra: 'A legacy can include achievements, cultural contributions, philanthropy, and the positive effects of one\'s actions on future generations. It is a way in which individuals are remembered and celebrated.',
    tag: ['#Impact', '#Contributions', '#Remembered']
},
{
    heading: 'Wealth',
    para: 'Wealth is an abundance of valuable assets, resources, or possessions, often measured in terms of financial worth. It includes money, property, investments, and other valuable holdings.',
    extra: 'Wealth can provide individuals and families with economic security and opportunities. It can be acquired through various means, including work, business ventures, investments, and inheritance.',
    tag: ['#Financial Abundance', '#Assets', '#Economic Security']
},
{
    heading: 'King',
    para: 'A king is a male monarch who rules over a kingdom or sovereign state. Kings often hold hereditary titles and exercise political and ceremonial authority.',
    extra: 'Throughout history, kings have played central roles in governance and leadership. Their powers and responsibilities can vary widely depending on the form of government and the era.',
    tag: ['#Monarch', '#Sovereign', '#Ruler']
},
{
    heading: 'Mogul',
    para: 'Mogul, often spelled "mogol," can refer to a powerful and influential person, especially in business, entertainment, or a specific industry. The term is sometimes used to describe individuals who have achieved significant success and wealth.',
    extra: 'In business, a mogul is typically a tycoon or magnate who has substantial control and influence over a particular sector or enterprise. Moguls are often associated with entrepreneurship and innovation.',
    tag: ['#Influential Person', '#Entrepreneurship', '#Success']
},
{
    heading: 'Monument',
    para: 'A monument is a physical structure or object created to commemorate, honor, or memorialize a person, event, or concept. Monuments are often built for their historical, cultural, or symbolic significance.',
    extra: 'Monuments can take various forms, including statues, plaques, buildings, and memorials. They serve as a means of preserving and conveying collective memory and heritage.',
    tag: ['#Commemoration', '#Memorial', '#Symbolism']
},
{
    heading: 'Inherit',
    para: 'To inherit means to receive assets, property, or rights from a deceased person as a beneficiary. It involves the transfer of possessions or wealth to the heirs or successors of the deceased individual.',
    extra: 'Inheritance often follows legal or familial processes and may involve taxes and legal formalities. Those who inherit assets become the rightful owners of the bequeathed property.',
    tag: ['#Receiving', '#Beneficiary', '#Asset Transfer']
},
{
    heading: 'Inheritance',
    para: 'Inheritance is the process by which individuals receive assets, property, or rights from a deceased person, often according to legal or familial arrangements, such as wills or inheritance laws.',
    extra: 'Inheritance can include monetary wealth, real estate, personal possessions, and other assets. It plays a crucial role in estate planning and the transfer of wealth between generations.',
    tag: ['#Legacy', '#Estate Planning', '#Succession']
},
{
    heading: 'Civil War',
    para: 'A civil war is a conflict between opposing groups or factions within the same country or state. It typically involves armed hostilities and political, social, or ideological differences.',
    extra: 'Civil wars can have profound and long-lasting effects on societies, leading to political upheaval, social divisions, and significant changes in governance.',
    tag: ['#Conflict', '#Internal Strife', '#Societal Impact']
},
{
    heading: 'Regent',
    para: 'A regent is a person appointed to govern a country, state, or organization on behalf of a monarch, leader, or ruler who is unable to rule due to minority, absence, or incapacity.',
    extra: 'Regents often have temporary authority and are responsible for the administration of government affairs during transitional periods. They play a crucial role in ensuring stability and continuity.',
    tag: ['#Governance', '#Leadership', '#Temporary Authority']
},
{
    heading: 'Vile',
    para: 'Vile is an adjective that describes something extremely unpleasant, morally reprehensible, or wicked. It is used to characterize actions, behaviors, or qualities that are considered despicable or evil.',
    extra: 'The term "vile" conveys a strong sense of disgust or contempt and is often used to express strong disapproval of something or someone\'s actions.',
    tag: ['#Despicable', '#Morally Reprehensible', '#Disgust']
},
{
    heading: 'Vie',
    para: 'To vie means to compete or strive for something, often in a competitive or ambitious manner. It involves seeking to outdo others or achieve a particular goal.',
    extra: 'Vying can take place in various contexts, including sports, business, politics, and personal pursuits. It reflects the human drive for success and recognition.',
    tag: ['#Competition', '#Striving', '#Ambition']
},
{
    heading: 'Dye',
    para: 'Dye is a substance used to color textiles, fabrics, or other materials. It can be derived from natural sources, such as plants and insects, or created synthetically.',
    extra: 'The art of dyeing has a rich history, with various cultures developing their dyeing techniques and color palettes. Dyes are used in clothing, art, and various industries.',
    tag: ['#Coloring', '#Textiles', '#Art']
},
{
    heading: 'Shards',
    para: 'Shards are broken fragments or pieces of a larger object, typically referring to broken pieces of pottery or glass.',
    extra: 'Archaeologists often study shards to gain insights into ancient cultures and civilizations. The discovery of shards can reveal information about pottery styles, craftsmanship, and historical context.',
    tag: ['#Fragments', '#Archaeology', '#Artifacts']
},
{
    heading: 'Pottery',
    para: 'Pottery is the art and craft of creating ceramic objects, such as clay vessels, bowls, and sculptures, by shaping and firing clay at high temperatures.',
    extra: 'Pottery has a long history and has been used for utilitarian and artistic purposes in cultures worldwide. It includes various techniques like hand-building, wheel-throwing, and glazing.',
    tag: ['#Ceramics', '#Craftsmanship', '#Art']
},
{
    heading: 'Messenger',
    para: 'A messenger is an individual or courier responsible for delivering messages, information, or important communications from one person or location to another.',
    extra: 'Messengers have played essential roles throughout history, ensuring the timely exchange of information in various contexts, including diplomacy, war, and everyday life.',
    tag: ['#Communication', '#Courier', '#Delivery']
},
{
    heading: 'Gunpowder',
    para: 'Gunpowder, also known as black powder, is a chemical mixture consisting of sulfur, charcoal, and potassium nitrate. It is used as a propellant in firearms and explosives.',
    extra: 'The invention of gunpowder revolutionized warfare and had significant historical implications. It played a key role in the development of firearms and artillery, changing the nature of conflict.',
    tag: ['#Explosive', '#Firearms', '#Propellant']
},
{
    heading: 'Gun',
    para: 'A gun is a portable firearm designed to discharge projectiles, such as bullets, through the force of expanding gases produced by chemical reactions within the firearm.',
    extra: 'Guns have evolved over centuries and have had a profound impact on warfare, self-defense, and hunting. They come in various types, including rifles, handguns, and shotguns, each with specific uses.',
    tag: ['#Firearm', '#Projectiles', '#Weapon']
},
{
    heading: 'Silk',
    para: 'Silk is a natural fiber produced by silkworms and used in the creation of textiles and fabrics. It is known for its softness, sheen, and luxurious feel.',
    extra: 'Silk has a rich history and was highly prized in ancient China, where it was a closely guarded secret. It became a valuable commodity in trade routes such as the Silk Road, facilitating cultural exchange.',
    tag: ['#Textiles', '#Luxury', '#Cultural Exchange']
},
{
    heading: 'Silver',
    para: 'Silver is a precious metal that is valued for its lustrous appearance, conductivity, and versatility. It has been used for coins, jewelry, and various industrial applications.',
    extra: 'Silver is known for its distinctive white color and has played a crucial role in trade and commerce. It is also a component of various alloys and has antimicrobial properties.',
    tag: ['#Precious Metal', '#Currency', '#Conductivity']
},
{
    heading: 'Gold',
    para: 'Gold is a precious metal known for its rarity, beauty, and high value. It has been used for currency, jewelry, and various decorative and industrial purposes throughout history.',
    extra: 'Gold is often associated with wealth and luxury and has played a significant role in economies and cultures worldwide. It is a symbol of value and durability.',
    tag: ['#Precious Metal', '#Currency', '#Wealth']
},
{
    heading: 'Empire',
    para: 'An empire is a large and politically centralized state or territory typically characterized by the dominance of one ruling authority or monarch over diverse regions, peoples, and cultures. Empires often expand through conquest and colonization.',
    extra: 'Historically, empires have played significant roles in shaping world history, economies, and societies. They have exerted control over vast territories and influenced the development of cultures and civilizations.',
    tag: ['#Political Power', '#Territorial Expansion', '#Dominance']
},
{
    heading: 'Scholars',
    para: 'Scholars are individuals who engage in systematic study, research, and the pursuit of knowledge in various academic, scientific, or intellectual fields. They contribute to the advancement of human understanding and the expansion of knowledge.',
    extra: 'Scholars may specialize in areas such as history, science, literature, philosophy, and more. They often conduct research, publish academic papers, and share their expertise through teaching and collaboration with peers.',
    tag: ['#Academics', '#Research', '#Knowledge']
},
{
    heading: 'Religion',
    para: 'Religion is a system of beliefs, practices, and values that often involve the worship of deities or a divine power. It provides a framework for understanding the spiritual, moral, and ethical aspects of life and the universe.',
    extra: 'Religions can vary widely, encompassing monotheistic faiths like Christianity and Islam, polytheistic traditions such as Hinduism, and non-theistic philosophies like Buddhism. They play significant roles in shaping cultures, ethics, and worldviews.',
    tag: ['#Beliefs', '#Spirituality', '#Faith']
},
{
    heading: 'Administration',
    para: 'Administration refers to the management, organization, and coordination of activities, resources, and operations within an entity or institution. It involves the implementation of policies, decision-making, and the oversight of daily functions.',
    extra: 'Administrative functions are critical in various sectors, including government, business, education, and healthcare. Effective administration ensures the efficient functioning of organizations and the achievement of their goals.',
    tag: ['#Management', '#Organization', '#Efficiency']
},
{
    heading: 'Politics',
    para: 'Politics encompasses the activities, processes, and principles associated with governance, public affairs, and the exercise of power within a society or nation. It involves decision-making, policy development, and the allocation of resources.',
    extra: 'Political systems can vary, including democracies, autocracies, and various forms of governance. Politics influences laws, regulations, and the distribution of benefits and responsibilities within a community. It is a central aspect of human societies.',
    tag: ['#Governance', '#Policy', '#Power']
},
{
    heading: 'Pillage',
    para: 'Pillage is the act of forcefully taking or plundering valuable resources, possessions, or wealth, often through acts of theft, destruction, or violence. It is typically associated with wartime or lawless situations.',
    extra: 'Pillage can have devastating consequences for communities and regions affected by it. It has been a common practice in history during conflicts, invasions, and the breakdown of social order.',
    tag: ['#Plunder', '#Conflict', '#Looting']
},
{
    heading: 'Innovation',
    para: 'Innovation refers to the process of creating, developing, and implementing new ideas, methods, products, or technologies that lead to positive change or improvement. It involves finding novel solutions to problems or challenges.',
    extra: 'Innovation can occur in various fields, including technology, business, science, and the arts. It is a driving force behind progress, economic growth, and the advancement of societies. Innovative thinking fosters creativity and drives evolution.',
    tag: ['#Creativity', '#Change', '#Progress']
},
{
    heading: 'Nomads',
    para: 'Nomads are people or communities who lead a migratory or itinerant way of life, often moving from one place to another rather than residing in a fixed location. Nomadic cultures are characterized by their adaptability to changing environments and reliance on mobile livelihoods.',
    extra: 'Nomadic societies may include pastoralists who raise livestock, hunter-gatherers, and others who follow seasonal patterns of migration. They have historically played essential roles in trade, cultural exchange, and the exploration of new territories.',
    tag: ['#Migratory Lifestyle', '#Cultural Adaptation', '#Nomadic Cultures']
},
{
    heading: 'Alliance',
    para: 'An alliance is a formal or informal agreement or partnership between individuals, groups, organizations, or nations with shared interests or common goals. Alliances are often formed to achieve mutual benefits, enhance security, or address common challenges.',
    extra: 'Alliances can take various forms, including political, military, economic, and social alliances. They promote cooperation and collaboration among participants and can be important in maintaining stability and addressing global issues.',
    tag: ['#Partnership', '#Cooperation', '#Common Goals']
},
{
    heading: 'Siege',
    para: 'A siege is a military strategy in which an army or force surrounds and isolates a fortified location, such as a city, with the intention of cutting off supplies and forcing surrender. Sieges can last for an extended period and often involve both offensive and defensive tactics.',
    extra: 'Historically, sieges have been employed in various conflicts and wars to capture or defend important strategic positions. They require careful planning and the use of siege engines and tactics to breach fortifications.',
    tag: ['#Military Strategy', '#Fortification', '#Blockade']
},
{
    heading: 'Holy Grail',
    para: 'The Holy Grail is a legendary and sacred object in various mythologies and medieval legends, most notably associated with the Christian tradition. It is often depicted as a chalice or dish used by Jesus Christ during the Last Supper and later said to possess mystical and divine properties.',
    extra: 'The quest for the Holy Grail has been a recurring theme in literature, art, and folklore. It represents the pursuit of a noble and often unattainable goal, embodying themes of faith, purity, and spiritual enlightenment.',
    tag: ['#Mythology', '#Legend', '#Quest']
},
{
    heading: 'Viscosity',
    para: 'Viscosity is a physical property of a fluid that measures its resistance to flow. It refers to the thickness or stickiness of a fluid, and it can vary from low viscosity (thin, easily flowing) to high viscosity (thick, resistant to flow).',
    extra: 'Viscosity plays a crucial role in various applications, including the automotive industry (engine lubricants), food industry (sauces and liquids), and pharmaceuticals (medicine formulations). It is typically measured in units such as poise or pascal-seconds (Pa·s).',
    tag: ['#Physics', '#Fluid Mechanics', '#Resistance to Flow']
},
{
    heading: 'Strong',
    para: 'Strong is an adjective that describes having a high degree of physical, mental, or emotional strength and resilience. It signifies the ability to endure challenges, exert force, or maintain a robust state of well-being.',
    extra: 'Strength can manifest in different ways, such as physical strength, mental fortitude, or emotional stability. Building and maintaining strength often involve physical exercise, mental training, and emotional self-care.',
    tag: ['#Strength', '#Resilience', '#Well-being']
},
{
    heading: 'Weak',
    para: "Weak is an adjective used to describe a lack of physical or mental strength, power, or resilience. It can refer to an individual's physical condition, character, or abilities, indicating a vulnerability or inability to withstand challenges or exert force.",
    extra: 'In various contexts, weakness can be temporary or chronic, and it may apply to physical health, emotional state, or moral character. Overcoming weakness often involves building strength, resilience, or seeking support.',
    tag: ['#Strength', '#Vulnerability', '#Resilience']
},
{
    heading: 'War',
    para: 'War is a state of organized and often armed conflict between different nations, groups, or entities. It typically involves large-scale hostilities, such as battles and military operations, and can have far-reaching consequences, including loss of life, destruction, and political and social upheaval.',
    extra: 'Throughout history, wars have been waged for various reasons, including territorial disputes, ideological differences, and resources. Efforts to prevent and resolve conflicts and promote peace are essential in the modern world.',
    tag: ['#Conflict', '#Military', '#Peace']
},
{
    heading: 'Sympathy',
    para: "Sympathy refers to the feelings of pity, sorrow, or compassion that one person may experience in response to another person's suffering or misfortune. It involves recognizing another's distress without necessarily sharing the same emotions or experiences.",
    extra: 'While sympathy shows a sense of caring and support, it may not involve the same level of emotional connection as empathy. Sympathetic individuals express concern and may offer comfort or assistance to those in need.',
    tag: ['#Compassion', '#Support', '#Empathy vs. Sympathy']
},
{
    heading: 'Empathy',
    para: "Empathy is the ability to understand and share the feelings, thoughts, and experiences of another person. It involves not only recognizing someone else's emotions but also being able to emotionally connect and show genuine concern and support.",
    extra: 'Empathy is considered a fundamental aspect of human social interaction and is often associated with increased understanding, compassion, and the ability to build strong interpersonal relationships. It plays a crucial role in fields such as psychology, counseling, and healthcare.',
    tag: ['#Emotions', '#Interpersonal Relationships', '#Compassion']
},
{
    heading: 'Psychology',
    para: 'Psychology is the scientific study of the human mind and behavior. It seeks to understand and explain various aspects of mental processes, emotions, cognition, and behavior through systematic research, observation, and analysis.',
    extra: 'Psychology encompasses various subfields, including clinical psychology, cognitive psychology, social psychology, and developmental psychology. It is applied in areas such as therapy, counseling, education, and organizational behavior.',
    tag: ['#Science', '#Mental Processes', '#Behavioral Science']
},
{
    heading: 'Trait',
    para: "A trait is a distinct characteristic or feature that can be observed in an individual's behavior, personality, or physical attributes. Traits are inherent qualities that contribute to an individual's uniqueness and are often influenced by genetic, environmental, and cultural factors.",
    extra: "In the field of psychology, traits are used to describe and study personality differences among individuals. Traits can be categorized as either personality traits, which relate to enduring patterns of behavior, or physical traits, which pertain to an individual's physical appearance and genetic makeup.",
    tag: ['#Psychology', '#Personality', '#Characteristics']
},
{
    heading: 'Strait',
    para: 'A strait is a narrow waterway or passage that connects two larger bodies of water, such as seas or oceans, and often serves as a natural channel for maritime navigation. Straits are typically characterized by their restricted width, which can create challenges for ships and vessels to navigate.',
    extra: 'Straits can be strategically important for international trade and transportation, and they often have historical and geopolitical significance. Examples of well-known straits include the Strait of Gibraltar, the Bosphorus Strait, and the Strait of Malacca.',
    tag: ['#Geography', '#Maritime Navigation', '#Waterway']
},
{
    heading: 'Pomodoro Technique',
    para: 'The Pomodoro Technique is a time management method developed by Francesco Cirillo in the late 1980s. It involves breaking work or tasks into intervals, traditionally 25 minutes in length, separated by short breaks. These intervals are referred to as "Pomodoros."',
    extra: 'The technique is designed to improve productivity and focus by encouraging individuals to work in short, focused bursts and then take regular breaks. It is named after the Italian word for "tomato" because Cirillo initially used a tomato-shaped kitchen timer to track his work intervals.',
    tag: ['#Time Management', '#Productivity', '#Work Technique']
},
{
    heading: 'Promo',
    para: 'A promo is a shortened form of the word "promotion" and refers to a marketing or advertising tactic used to promote a product, service, event, or brand. Promos are designed to attract and engage customers, often by offering discounts, incentives, or special offers.',
    extra: 'Promos can take various forms, including advertisements, coupons, contests, and giveaways. They are a common strategy used by businesses and organizations to increase awareness, drive sales, and build customer loyalty.',
    tag: ['#Marketing', '#Advertising', '#Promotion Strategy']
},
{
    heading: 'Prom',
    para: 'A prom, short for "promenade," is a formal or semi-formal event typically held at the end of the high school academic year. It is a special social gathering where students dress elegantly, often in formal attire, and come together to celebrate and dance.',
    extra: 'Proms are a significant cultural tradition in many countries, especially in the United States, and often include activities like dancing, music, the crowning of a prom king and queen, and the exchange of prom favors or keepsakes.',
    tag: ['#High School', '#Formal Event', '#Social Tradition']
},
{
    heading: 'Buoyancy',
    para: 'Buoyancy is a physical property of fluids, such as water or air, that describes the upward force exerted by a fluid on an object submerged in it. This force opposes the weight of the object and causes it to float or rise in the fluid.',
    extra: "Archimedes' principle, named after the ancient Greek scientist Archimedes, explains buoyancy and states that the buoyant force is equal to the weight of the displaced fluid. Buoyancy plays a crucial role in various fields, including ship design, aviation, and underwater exploration.",
    tag: ['#Physics', '#Fluid Mechanics', "#Archimedes' Principle"]
},
{
    heading: 'Archipelago',
    para: 'An archipelago is a geographical term that refers to a group or chain of islands that are closely spaced and often surrounded by a body of water, such as the sea or an ocean. Archipelagos can vary in size, from small clusters of islands to vast island chains.',
    extra: 'Some well-known archipelagos include the Hawaiian Islands in the Pacific Ocean, the Maldives in the Indian Ocean, and the Greek Islands in the Mediterranean Sea.',
    tag: ['#Geography', '#Islands', '#Oceanography']
},
{
    heading: 'Narcotics',
    para: 'Narcotics are a category of drugs that primarily include substances derived from opium poppy plants, such as heroin, morphine, and codeine. These drugs have strong pain-relieving properties and are often used for medical purposes, but they can also have a high potential for abuse and addiction.',
    extra: 'The term "narcotics" is sometimes used more broadly to refer to any illegal or controlled substances, including not only opiate-based drugs but also cocaine, marijuana, and synthetic drugs.',
    tag: ['#Drugs', '#Opioids', '#Addiction']
},
{
    heading: 'Narcissism',
    para: "Narcissism is a psychological term that refers to a personality trait or disorder characterized by an excessive focus on oneself, one's appearance, abilities, or achievements, often accompanied by a lack of empathy for others and a constant need for admiration and validation.",
    extra: 'Narcissism can range from a healthy level of self-confidence and self-esteem to pathological narcissism, such as narcissistic personality disorder (NPD), which is a more severe and rigid condition.',
    tag: ['#Psychology', '#Personality Trait', '#Narcissistic Personality Disorder']
},
{
    heading: 'Narcissist',
    para: 'A narcissist is an individual who displays excessive self-love, self-importance, and an exaggerated sense of their own abilities and achievements. They often lack empathy for others and seek constant admiration and validation from those around them.',
    extra: 'Narcissistic personality disorder (NPD) is a psychological condition characterized by a pervasive pattern of narcissistic behavior and a profound need for attention and admiration.',
    tag: ['#Psychology', '#Personality Disorder', '#Narcissism']
}



];

// Function to display search results as a list
function displaySearchResults(results) {
  if (!results.length) {
    searchResultsContainer.innerHTML = '';
    return;
  }

  searchResultsContainer.innerHTML = '';

  results.forEach(item => {
    const resultItem = document.createElement('div');
    resultItem.textContent = item.heading;
    resultItem.className = 'search-result';

    resultItem.addEventListener('click', () => {
      updateCardContent(item);
    });

    searchResultsContainer.appendChild(resultItem);
  });
}

// Function to update card content
function updateCardContent(item) {
  cardHeading.textContent = item.heading;
  cardPara.textContent = item.para;
  cardExtra.textContent = item.extra;
  cardTag.textContent = item.tag;
}

// Search input event listener
searchInput.addEventListener('input', () => {
  const query = searchInput.value.toLowerCase();

  if (!query.trim()) {
    searchResultsContainer.innerHTML = ''; // Clear the search results container
    return;
  }

  const searchResults = headingsData.filter(item =>
    item.heading.toLowerCase().includes(query)
  );

  displaySearchResults(searchResults);
});

// Blur event listener for the search input
searchInput.addEventListener('blur', () => {
  // Delay clearing the search results to allow user interaction
  setTimeout(() => {
    searchResultsContainer.innerHTML = '';
  }, 200);
});