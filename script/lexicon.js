const searchInput = document.getElementById('searchInput');
const searchResultsContainer = document.getElementById('searchResultsContainer');
const cardHeading = document.getElementById('cardHeading');
const cardPara = document.getElementById('cardPara');
const cardExtra = document.getElementById('cardExtra');
const cardTag = document.getElementById('cardTag');

// Data
const headingsData = [
  {
    heading: 'Armageddon',
    para: 'Armageddon is a term that refers to a catastrophic and apocalyptic event or conflict of immense proportions, often associated with the end of the world or a major showdown between opposing forces.',
    extra: 'In religious contexts, Armageddon is mentioned as a final battle between good and evil in some belief systems, particularly in Christian theology.',
    tags: ['Apocalypse', 'End Times', 'Eschatology']
  },
  
  {
    heading: 'Dialect',
    para: 'A dialect is a specific form of a language spoken by a particular group of people or in a specific region. It encompasses variations in pronunciation, vocabulary, grammar, and sometimes even sentence structure.',
    extra: 'Dialects can emerge due to geographic isolation, cultural factors, historical influences, or social distinctions. They are often characterized by unique linguistic features and expressions.',
    tags: ['Language Variation', 'Regional Speech', 'Cultural Influence']
  },
  {
    heading: 'Exodus',
    para: 'An exodus refers to a mass departure or migration of a large group of people from one place to another, often due to political, social, or environmental factors. It can involve the relocation of a population from a specific region or country.',
    extra: 'The term "exodus" is frequently associated with historical events, such as the biblical Exodus of the Israelites from Egypt. Exodus can result from factors like conflict, persecution, natural disasters, or economic conditions.',
    tags: ['Migration', 'Mass Departure', 'Relocation']
  },
  {
    heading: 'Voyage',
    para: 'A voyage is a journey or expedition, typically by sea or through unknown or distant regions. It often implies travel over a considerable distance, and it can be for various purposes, such as exploration, trade, or adventure.',
    extra: 'Voyages have played a significant role in human history, including the Age of Exploration when explorers embarked on voyages to discover new lands and trade routes. Voyages can also be undertaken for leisure and cultural exchange.',
    tags: ['Journey', 'Sea Travel', 'Exploration']
  },
  {
    heading: 'Aqueduct',
    para: 'An aqueduct is a man-made structure or system designed to transport water, often over long distances, from one location to another. It is used to supply water for various purposes, including drinking, irrigation, and industrial use.',
    extra: 'Aqueducts can take various forms, including open channels, elevated bridges, and underground tunnels, depending on the terrain and engineering requirements. They have been used by ancient civilizations and are still employed in modern water supply systems.',
    tags: ['Water Transport', 'Infrastructure', 'Water Supply']
  },
  {
    heading: 'Colosseum',
    para: 'The Colosseum, also known as the Flavian Amphitheatre, is an ancient Roman amphitheater located in Rome, Italy. It is one of the most iconic and well-preserved ancient structures in the world.',
    extra: 'The Colosseum was used for various forms of entertainment, including gladiator contests and public spectacles. It could hold tens of thousands of spectators and is a symbol of Roman engineering and culture.',
    tags: ['Ancient Rome', 'Amphitheater', 'Historical Landmark']
  },
  {
    heading: 'Indenture',
    para: 'Indenture is a legal contract or agreement between two or more parties, often in a written document with indented edges (hence the name). It typically outlines specific terms, conditions, or obligations to be fulfilled.',
    extra: 'Indentures have historically been used for various purposes, including apprenticeship agreements, land transactions, and labor contracts. They often involve a binding commitment or obligation.',
    tags: ['Contract', 'Agreement', 'Legal Document']
  },
  {
    heading: 'Delicacy',
    para: 'Delicacy has multiple meanings, but it often refers to something rare, exquisite, or considered a luxury, especially in the context of food. Delicacies are often highly prized for their unique flavors and qualities.',
    extra: 'Delicacies can include foods like caviar, truffles, or rare seafood. The term can also be used more broadly to describe anything of great value, fragility, or sensitivity.',
    tags: ['Exquisite', 'Luxury', 'Rare']
  },
  {
    heading: 'Ailments',
    para: 'Ailments are physical or mental health conditions or illnesses that cause discomfort, distress, or impairment of normal functioning. They can range from minor illnesses to more serious medical conditions.',
    extra: 'Ailments may include symptoms like fever, pain, fatigue, or psychological distress. The term is commonly used to refer to health issues that require medical attention or treatment.',
    tags: ['Health Conditions', 'Illness', 'Medical Treatment']
  },
  {
    heading: 'Savage',
    para: 'Savage is an adjective used to describe behavior or actions that are extremely brutal, violent, or uncivilized. It implies a lack of restraint and adherence to social norms.',
    extra: 'The term "savage" has been historically used in colonial and ethnocentric contexts to label indigenous or non-Western cultures as uncivilized. Its usage has been criticized as derogatory and biased.',
    tags: ['Brutal', 'Uncivilized', 'Ethnocentrism']
  },
  {
    heading: 'Atrocity',
    para: 'An atrocity is an extremely cruel, brutal, or heinous act or event that causes great suffering, harm, or outrage. It often involves actions that violate moral or ethical standards.',
    extra: 'Atrocities can take various forms, including acts of violence, mass killings, and human rights abuses. They are considered grave violations of humanitarian and ethical norms.',
    tags: ['Cruelty', 'Harm', 'Human Rights']
  },
  {
    heading: 'Moat',
    para: 'A moat is a deep, wide ditch or trench that surrounds a castle, fortification, or building. It is typically filled with water and serves as a defensive barrier against attackers.',
    extra: 'Moats were historically used as defensive features to hinder access to a structure and make it more difficult for besieging forces to breach its walls. Today, moats are primarily of historical or aesthetic significance.',
    tags: ['Defense', 'Castle', 'Fortification']
  },
  {
    heading: 'Justice',
    para: 'Justice is the principle of fairness, righteousness, and the equitable treatment of individuals within a legal and moral framework. It involves the upholding of rights, the rule of law, and the resolution of disputes.',
    extra: 'Justice encompasses concepts such as due process, accountability, and the protection of human rights. It is often pursued through legal systems and institutions to ensure impartiality and fairness.',
    tags: ['Fairness', 'Legal System', 'Human Rights']
  },
  {
    heading: 'Invasion',
    para: 'An invasion is the act of entering and taking control of a foreign territory or region, typically by military force. Invasions are often characterized by the occupation and subjugation of the invaded area.',
    extra: 'Invasions can be motivated by territorial expansion, conquest, or strategic objectives. They have historically been a source of conflict and geopolitical change.',
    tags: ['Military Action', 'Occupation', 'Territorial Control']
  },
  {
    heading: 'Slaughter',
    para: 'Slaughter refers to the act of killing animals or humans, often in a brutal or large-scale manner. It is associated with violence and the taking of lives.',
    extra: 'Slaughter can occur for various purposes, including food production, hunting, or acts of violence in conflict. It is a term that conveys the loss of life and is often used in the context of brutality or mass killings.',
    tags: ['Killing', 'Violence', 'Brutality']
  },
  {
    heading: 'Clan',
    para: 'A clan is a social group or extended family unit, often with a shared ancestry or common lineage. Clans are typically characterized by close-knit relationships and may have their own traditions and customs.',
    extra: 'Clans have existed in various cultures and regions throughout history, and they can play important roles in social organization and identity. Clan members often support one another and share responsibilities.',
    tags: ['Social Group', 'Lineage', 'Traditions']
  },
  {
    heading: 'Strife',
    para: 'Strife refers to conflict, discord, or disagreement, often characterized by intense and hostile disputes or struggles between individuals, groups, or entities.',
    extra: 'Strife can occur in various contexts, including personal relationships, politics, and social dynamics. It can lead to tension, division, and, in some cases, open confrontations.',
    tags: ['Conflict', 'Disagreement', 'Hostility']
  },
  {
    heading: 'Destitute',
    para: 'Destitute is an adjective used to describe individuals or groups who are extremely poor and lacking basic necessities, such as food, shelter, and clothing. It implies a state of extreme poverty and deprivation.',
    extra: 'People who are destitute often face significant hardships and challenges in meeting their basic needs. Social welfare programs and charitable efforts may provide assistance to destitute individuals.',
    tags: ['Poverty', 'Deprivation', 'Hardship']
  },
  {
    heading: 'Warlord',
    para: 'A warlord is a military leader, often with considerable power and influence, who commands armed forces and may exercise control over a specific region or territory through force and coercion.',
    extra: 'Warlords can emerge in times of conflict or political instability and may govern autonomously, challenging central authorities. Their rule is often characterized by the use of force to maintain control.',
    tags: ['Military Leader', 'Power', 'Conflict']
  },
  {
    heading: 'Barbarian',
    para: 'A barbarian is a historical term that originally referred to a person or group perceived as culturally, linguistically, or socially inferior or foreign by the standards of a particular civilization or culture.',
    extra: 'The term "barbarian" has been used in various historical contexts to describe outsiders or non-citizens. It often carried a pejorative or derogatory connotation, implying a lack of refinement or civility.',
    tags: ['Cultural Perception', 'Outsider', 'Historical Term']
  },
  {
    heading: 'Imperial',
    para: 'Imperial refers to something related to an empire or the characteristics associated with imperial rule, such as dominance, expansion, and influence over other territories and peoples.',
    extra: 'Imperialism is a historical and political concept where a powerful nation extends its authority and control over other regions. Imperial policies have shaped world history and international relations.',
    tags: ['Empire', 'Dominance', 'Expansion']
  },
  {
    heading: 'Exile',
    para: 'Exile is the forced or voluntary absence of an individual or group from their homeland or native country, often due to political, social, or personal reasons. It involves living in a foreign land or place.',
    extra: 'Exile can result from political persecution, conflicts, or personal choices. It can be a challenging experience and may involve a sense of displacement and loss of one\'s familiar environment.',
    tags: ['Forced Absence', 'Displacement', 'Homeland']
  },
  {
    heading: 'Nationalism',
    para: 'Nationalism is a political ideology or sentiment characterized by a strong attachment to one\'s nation or country, often involving pride in its culture, history, and identity.',
    extra: 'Nationalism can have both positive and negative manifestations. While it can foster unity and patriotism, it can also lead to conflicts when it becomes extreme or exclusionary.',
    tags: ['Patriotism', 'National Identity', 'Political Ideology']
  },
  {
    heading: 'Liberal',
    para: 'Liberal, when used in a political or philosophical context, refers to a broad range of ideas and beliefs that emphasize individual rights, freedoms, and progressive social policies.',
    extra: 'Liberalism is often associated with democratic systems that protect civil liberties, promote social equality, and advocate for government intervention in areas such as education and healthcare.',
    tags: ['Individual Rights', 'Progressive Policies', 'Social Equality']
  },
  {
    heading: 'Regime',
    para: 'A regime is a system of government or ruling authority that governs a country or political entity. It encompasses the leadership, policies, and structures that define a government.',
    extra: 'Regimes can be democratic, authoritarian, or of other forms, and they can vary widely in their ideologies and approaches. The term is often used to describe governments, especially those with centralized authority.',
    tags: ['Government System', 'Leadership', 'Policies']
  },
  {
    heading: 'Legal',
    para: 'Legal refers to something that is in accordance with the law, regulations, or established rules and norms. It pertains to actions, processes, or matters that are recognized and permissible under the legal system.',
    extra: 'Legal principles and standards are essential for maintaining order, resolving disputes, and upholding justice in societies. Legal matters are often adjudicated in courts of law.',
    tags: ['Lawful', 'Compliance', 'Legal System']
  },
  {
    heading: 'Constitution',
    para: 'A constitution is a fundamental set of laws, principles, and rules that establish the framework for governance in a country or organization. It defines the structure of government and the rights and responsibilities of citizens.',
    extra: 'Constitutions can take various forms, including written and unwritten, and may be amended or revised over time. They serve as the supreme legal authority in a given jurisdiction.',
    tags: ['Fundamental Laws', 'Governance Framework', 'Rights and Responsibilities']
  },
  {
    heading: 'Coup',
    para: 'A coup, short for coup d\'état, is a sudden and often violent overthrow of a government or ruling authority, typically carried out by a faction within the existing power structure.',
    extra: 'Coups can result in changes of leadership, government, or regime. They are often motivated by political, military, or ideological factors and can lead to significant political upheaval.',
    tags: ['Overthrow', 'Political Change', 'Regime Change']
  },
  {
    heading: 'Consulate',
    para: 'A consulate is a diplomatic office or mission established by one country in another, typically in a foreign city, to provide services and assistance to its citizens, facilitate trade, and engage in diplomatic relations.',
    extra: 'Consulates play important roles in international diplomacy and often offer consular services such as visa issuance, passport renewal, and assistance to nationals living abroad.',
    tags: ['Diplomacy', 'Consular Services', 'International Relations']
  },
  {
    heading: 'Wise',
    para: 'Wise is an adjective used to describe someone who possesses wisdom, sound judgment, and knowledge gained through experience. It implies the ability to make thoughtful and informed decisions.',
    extra: 'Wise individuals are often respected for their guidance and insights. Wisdom can be acquired over time and is associated with qualities such as prudence and discernment.',
    tags: ['Wisdom', 'Sound Judgment', 'Knowledge']
  },
  {
    heading: 'Oligarchy',
    para: 'Oligarchy is a system of government or social structure in which power is concentrated in the hands of a small, privileged, and often wealthy group or elite.',
    extra: 'In an oligarchic system, a few individuals or families exert significant influence over political, economic, and social affairs. Oligarchies can limit access to power and resources for the broader population.',
    tags: ['Power Concentration', 'Privilege', 'Elite Control']
  },
  {
    heading: 'Fraternity',
    para: 'Fraternity refers to a group or organization of people who share common interests, goals, or values and often form close bonds of friendship and mutual support. It can also refer to the concept of brotherhood.',
    extra: 'Fraternities are commonly associated with universities and colleges, where they promote camaraderie and social activities among members. The term can also be used more broadly to describe solidarity and unity.',
    tags: ['Brotherhood', 'Mutual Support', 'Camaraderie']
  },
  {
    heading: 'Equality',
    para: 'Equality is the principle of fairness and equal treatment for all individuals, regardless of their background, characteristics, or circumstances. It involves the absence of discrimination or bias.',
    extra: 'Equality can pertain to various aspects of life, including gender equality, racial equality, and economic equality. It is often a goal in the pursuit of social justice and human rights.',
    tags: ['Fairness', 'Non-Discrimination', 'Social Justice']
  },
  {
    heading: 'Liberty',
    para: 'Liberty, often referred to as freedom, is the state of being free from oppression, restrictions, or external control. It encompasses the ability to make choices and pursue individual rights and interests.',
    extra: 'Liberty is a fundamental value in democracies and societies that prioritize individual rights and civil liberties. It includes freedom of speech, religion, and assembly.',
    tags: ['Freedom', 'Individual Rights', 'Civil Liberties']
  },
  {
    heading: 'Extremism',
    para: 'Extremism refers to radical or extreme beliefs, ideologies, or actions that deviate significantly from mainstream or moderate views. It often involves a willingness to use violence or force to advance a cause.',
    extra: 'Extremist ideologies can be political, religious, or ideological and may pose threats to societal stability and security. Combating extremism is a concern for governments and communities.',
    tags: ['Radicalism', 'Violence', 'Ideology']
  },
  {
    heading: 'Autocracy',
    para: 'Autocracy is a system of government in which a single individual, often a monarch or dictator, holds absolute and unchecked power, making decisions without the consent of others.',
    extra: 'Autocracies are characterized by the concentration of authority in one person or a small group. They can limit political freedoms and civil liberties, as power is highly centralized.',
    tags: ['Absolute Power', 'Authoritarianism', 'Centralized Rule']
  },
  {
    heading: 'Democracy',
    para: 'Democracy is a system of government in which the people have the authority to make decisions through voting, typically in free and fair elections. It emphasizes the participation of citizens in the decision-making process.',
    extra: 'Democracy values individual rights, freedom of expression, and the protection of minority interests. It can take various forms, including direct democracy and representative democracy.',
    tags: ['Government System', 'Citizen Participation', 'Elections']
  },
  {
    heading: 'Republic',
    para: 'A republic is a form of government in which the country is considered a "public matter" and political power is held by elected officials, often with a president serving as the head of state.',
    extra: 'Republics emphasize the rule of law, representation of citizens, and the protection of individual rights. They can take various forms, including democratic republics, where leaders are elected by the people.',
    tags: ['Government', 'Elected Officials', 'Rule of Law']
  },
  {
    heading: 'Chaos',
    para: 'Chaos refers to a state of complete disorder, confusion, and unpredictability. It is characterized by the absence of organization or control.',
    extra: 'In various contexts, chaos can be a temporary and natural state, such as in chaotic systems in physics and mathematics. However, it is often used to describe situations of turmoil and instability.',
    tags: ['Disorder', 'Confusion', 'Unpredictability']
  },
  {
    heading: 'Scepter',
    para: 'A scepter is an ornamental staff or rod, often carried by a monarch or ruler as a symbol of authority and sovereignty. It is typically embellished with decorative elements and can represent the ruler\'s right to rule.',
    extra: 'Scepters have been used in various cultures and historical periods to signify leadership and power. They are often seen in ceremonial and royal contexts, such as coronations and formal events.',
    tags: ['Symbol of Authority', 'Ceremonial Staff', 'Sovereignty']
  },
  {
    heading: 'Herald',
    para: 'A herald is a person or official who proclaims important news, announcements, or messages, often in a formal or ceremonial manner. Heralds have historically played roles in conveying royal decrees, news of battles, and other significant events.',
    extra: 'The term "herald" can also refer to a sign or indicator of something to come, and it is often associated with the concept of announcing or heralding a new era or change.',
    tags: ['Announcement', 'Messenger', 'Proclamation']
  },
  {
    heading: 'Chronicle',
    para: 'A chronicle is a historical record or narrative that documents events in chronological order. It serves as a written account of significant occurrences, often in the form of a continuous narrative.',
    extra: 'Chronicles are valuable sources for historians and researchers, providing insights into the past, including political developments, social changes, and cultural trends. They can take the form of books, manuscripts, or historical writings.',
    tags: ['Historical Record', 'Narrative', 'Documentation']
  },
  {
    heading: 'Recursion',
    para: 'Recursion is a programming and mathematical concept where a function or process calls itself in a repetitive and self-referential manner. It is often used to solve problems that can be broken down into smaller, similar sub-problems.',
    extra: 'Recursion is a fundamental technique in computer science and mathematics and is employed in algorithms, data structures, and problem-solving. It allows for elegant and concise solutions to complex problems.',
    tags: ['Programming', 'Mathematics', 'Problem-Solving']
  },
  {
    heading: 'Extravagant',
    para: 'Extravagant is an adjective used to describe something that is excessive, lavish, or opulent in nature. It implies a lack of restraint or a willingness to spend or display extravagance.',
    extra: 'Extravagant lifestyles, spending, or events are often associated with luxury and a desire for conspicuous consumption. The term can be applied to various aspects of life, such as fashion, celebrations, or purchases.',
    tags: ['Lavish', 'Opulence', 'Excess']
  },
  {
    heading: 'Trade',
    para: 'Trade is the exchange of goods, services, or commodities between individuals, groups, or nations. It is a fundamental economic activity that facilitates the distribution of products and resources.',
    extra: 'Trade can occur at local, national, or international levels and plays a central role in economic development and globalization. It involves buying, selling, and bartering various goods and services.',
    tags: ['Exchange', 'Commerce', 'Economic Activity']
  },
  {
    heading: 'Annex',
    para: 'To annex means to incorporate or attach a territory, region, or political entity into another, often larger, one. Annexation typically involves the extension of sovereignty and control over the annexed area.',
    extra: 'Annexations can occur through political agreements, treaties, or military actions. They have been historically employed by nations to expand their territories or assert dominance.',
    tags: ['Incorporation', 'Territorial Expansion', 'Sovereignty']
  },
  {
    heading: 'Realm',
    para: 'A realm is a territory, domain, or sphere of influence ruled or governed by a particular authority, such as a monarch or government. It represents a distinct and often defined area or jurisdiction.',
    extra: 'Realms can refer to physical territories, but they can also extend to metaphorical or conceptual domains, such as the realm of ideas or the realm of politics. The term conveys the idea of control or sovereignty.',
    tags: ['Territory', 'Jurisdiction', 'Sphere of Influence']
  },
  {
    heading: 'Famine',
    para: 'Famine is a severe and widespread scarcity of food, resulting in hunger, malnutrition, and sometimes starvation. Famines are typically caused by factors such as crop failure, food shortages, or political and environmental crises.',
    extra: 'Famines have historically led to devastating consequences for affected populations, including loss of life and long-term health problems. They often require humanitarian efforts to alleviate suffering.',
    tags: ['Food Scarcity', 'Hunger', 'Humanitarian Crisis']
  },
  {
    heading: 'Legacy',
    para: 'Legacy refers to the lasting impact, influence, or contributions that an individual, organization, or event leaves behind. It often encompasses the positive or significant aspects of a person\'s life or work.',
    extra: 'A legacy can include achievements, cultural contributions, philanthropy, and the positive effects of one\'s actions on future generations. It is a way in which individuals are remembered and celebrated.',
    tags: ['Impact', 'Contributions', 'Remembered']
  },
  {
    heading: 'Wealth',
    para: 'Wealth is an abundance of valuable assets, resources, or possessions, often measured in terms of financial worth. It includes money, property, investments, and other valuable holdings.',
    extra: 'Wealth can provide individuals and families with economic security and opportunities. It can be acquired through various means, including work, business ventures, investments, and inheritance.',
    tags: ['Financial Abundance', 'Assets', 'Economic Security']
  },
  {
    heading: 'King',
    para: 'A king is a male monarch who rules over a kingdom or sovereign state. Kings often hold hereditary titles and exercise political and ceremonial authority.',
    extra: 'Throughout history, kings have played central roles in governance and leadership. Their powers and responsibilities can vary widely depending on the form of government and the era.',
    tags: ['Monarch', 'Sovereign', 'Ruler']
  },
  {
    heading: 'Mogul',
    para: 'Mogul, often spelled "mogol," can refer to a powerful and influential person, especially in business, entertainment, or a specific industry. The term is sometimes used to describe individuals who have achieved significant success and wealth.',
    extra: 'In business, a mogul is typically a tycoon or magnate who has substantial control and influence over a particular sector or enterprise. Moguls are often associated with entrepreneurship and innovation.',
    tags: ['Influential Person', 'Entrepreneurship', 'Success']
  },
  {
    heading: 'Monument',
    para: 'A monument is a physical structure or object created to commemorate, honor, or memorialize a person, event, or concept. Monuments are often built for their historical, cultural, or symbolic significance.',
    extra: 'Monuments can take various forms, including statues, plaques, buildings, and memorials. They serve as a means of preserving and conveying collective memory and heritage.',
    tags: ['Commemoration', 'Memorial', 'Symbolism']
  },
  {
    heading: 'Inherit',
    para: 'To inherit means to receive assets, property, or rights from a deceased person as a beneficiary. It involves the transfer of possessions or wealth to the heirs or successors of the deceased individual.',
    extra: 'Inheritance often follows legal or familial processes and may involve taxes and legal formalities. Those who inherit assets become the rightful owners of the bequeathed property.',
    tags: ['Receiving', 'Beneficiary', 'Asset Transfer']
  },
  {
    heading: 'Inheritance',
    para: 'Inheritance is the process by which individuals receive assets, property, or rights from a deceased person, often according to legal or familial arrangements, such as wills or inheritance laws.',
    extra: 'Inheritance can include monetary wealth, real estate, personal possessions, and other assets. It plays a crucial role in estate planning and the transfer of wealth between generations.',
    tags: ['Legacy', 'Estate Planning', 'Succession']
  },  
  {
    heading: 'Civil War',
    para: 'A civil war is a conflict between opposing groups or factions within the same country or state. It typically involves armed hostilities and political, social, or ideological differences.',
    extra: 'Civil wars can have profound and long-lasting effects on societies, leading to political upheaval, social divisions, and significant changes in governance.',
    tags: ['Conflict', 'Internal Strife', 'Societal Impact']
  },
  {
    heading: 'Regent',
    para: 'A regent is a person appointed to govern a country, state, or organization on behalf of a monarch, leader, or ruler who is unable to rule due to minority, absence, or incapacity.',
    extra: 'Regents often have temporary authority and are responsible for the administration of government affairs during transitional periods. They play a crucial role in ensuring stability and continuity.',
    tags: ['Governance', 'Leadership', 'Temporary Authority']
  },
  {
    heading: 'Vile',
    para: 'Vile is an adjective that describes something extremely unpleasant, morally reprehensible, or wicked. It is used to characterize actions, behaviors, or qualities that are considered despicable or evil.',
    extra: 'The term "vile" conveys a strong sense of disgust or contempt and is often used to express strong disapproval of something or someone\'s actions.',
    tags: ['Despicable', 'Morally Reprehensible', 'Disgust']
  },
  {
    heading: 'Vie',
    para: 'To vie means to compete or strive for something, often in a competitive or ambitious manner. It involves seeking to outdo others or achieve a particular goal.',
    extra: 'Vying can take place in various contexts, including sports, business, politics, and personal pursuits. It reflects the human drive for success and recognition.',
    tags: ['Competition', 'Striving', 'Ambition']
  },
  {
    heading: 'Dye',
    para: 'Dye is a substance used to color textiles, fabrics, or other materials. It can be derived from natural sources, such as plants and insects, or created synthetically.',
    extra: 'The art of dyeing has a rich history, with various cultures developing their dyeing techniques and color palettes. Dyes are used in clothing, art, and various industries.',
    tags: ['Coloring', 'Textiles', 'Art']
  },
  {
    heading: 'Shards',
    para: 'Shards are broken fragments or pieces of a larger object, typically referring to broken pieces of pottery or glass.',
    extra: 'Archaeologists often study shards to gain insights into ancient cultures and civilizations. The discovery of shards can reveal information about pottery styles, craftsmanship, and historical context.',
    tags: ['Fragments', 'Archaeology', 'Artifacts']
  },
  {
    heading: 'Pottery',
    para: 'Pottery is the art and craft of creating ceramic objects, such as clay vessels, bowls, and sculptures, by shaping and firing clay at high temperatures.',
    extra: 'Pottery has a long history and has been used for utilitarian and artistic purposes in cultures worldwide. It includes various techniques like hand-building, wheel-throwing, and glazing.',
    tags: ['Ceramics', 'Craftsmanship', 'Art']
  },
  {
    heading: 'Messenger',
    para: 'A messenger is an individual or courier responsible for delivering messages, information, or important communications from one person or location to another.',
    extra: 'Messengers have played essential roles throughout history, ensuring the timely exchange of information in various contexts, including diplomacy, war, and everyday life.',
    tags: ['Communication', 'Courier', 'Delivery']
  },
  {
    heading: 'Gunpowder',
    para: 'Gunpowder, also known as black powder, is a chemical mixture consisting of sulfur, charcoal, and potassium nitrate. It is used as a propellant in firearms and explosives.',
    extra: 'The invention of gunpowder revolutionized warfare and had significant historical implications. It played a key role in the development of firearms and artillery, changing the nature of conflict.',
    tags: ['Explosive', 'Firearms', 'Propellant']
  },
  {
    heading: 'Gun',
    para: 'A gun is a portable firearm designed to discharge projectiles, such as bullets, through the force of expanding gases produced by chemical reactions within the firearm.',
    extra: 'Guns have evolved over centuries and have had a profound impact on warfare, self-defense, and hunting. They come in various types, including rifles, handguns, and shotguns, each with specific uses.',
    tags: ['Firearm', 'Projectiles', 'Weapon']
  },
  {
    heading: 'Silk',
    para: 'Silk is a natural fiber produced by silkworms and used in the creation of textiles and fabrics. It is known for its softness, sheen, and luxurious feel.',
    extra: 'Silk has a rich history and was highly prized in ancient China, where it was a closely guarded secret. It became a valuable commodity in trade routes such as the Silk Road, facilitating cultural exchange.',
    tags: ['Textiles', 'Luxury', 'Cultural Exchange']
  },
  {
    heading: 'Silver',
    para: 'Silver is a precious metal that is valued for its lustrous appearance, conductivity, and versatility. It has been used for coins, jewelry, and various industrial applications.',
    extra: 'Silver is known for its distinctive white color and has played a crucial role in trade and commerce. It is also a component of various alloys and has antimicrobial properties.',
    tags: ['Precious Metal', 'Currency', 'Conductivity']
  },
  {
    heading: 'Gold',
    para: 'Gold is a precious metal known for its rarity, beauty, and high value. It has been used for currency, jewelry, and various decorative and industrial purposes throughout history.',
    extra: 'Gold is often associated with wealth and luxury and has played a significant role in economies and cultures worldwide. It is a symbol of value and durability.',
    tags: ['Precious Metal', 'Currency', 'Wealth']
  },
  {
    heading: 'Empire',
    para: 'An empire is a large and politically centralized state or territory typically characterized by the dominance of one ruling authority or monarch over diverse regions, peoples, and cultures. Empires often expand through conquest and colonization.',
    extra: 'Historically, empires have played significant roles in shaping world history, economies, and societies. They have exerted control over vast territories and influenced the development of cultures and civilizations.',
    tags: ['Political Power', 'Territorial Expansion', 'Dominance']
  },
  {
    heading: 'Scholars',
    para: 'Scholars are individuals who engage in systematic study, research, and the pursuit of knowledge in various academic, scientific, or intellectual fields. They contribute to the advancement of human understanding and the expansion of knowledge.',
    extra: 'Scholars may specialize in areas such as history, science, literature, philosophy, and more. They often conduct research, publish academic papers, and share their expertise through teaching and collaboration with peers.',
    tags: ['Academics', 'Research', 'Knowledge']
  },
  {
    heading: 'Religion',
    para: 'Religion is a system of beliefs, practices, and values that often involve the worship of deities or a divine power. It provides a framework for understanding the spiritual, moral, and ethical aspects of life and the universe.',
    extra: 'Religions can vary widely, encompassing monotheistic faiths like Christianity and Islam, polytheistic traditions such as Hinduism, and non-theistic philosophies like Buddhism. They play significant roles in shaping cultures, ethics, and worldviews.',
    tags: ['Beliefs', 'Spirituality', 'Faith']
  },
  {
    heading: 'Administration',
    para: 'Administration refers to the management, organization, and coordination of activities, resources, and operations within an entity or institution. It involves the implementation of policies, decision-making, and the oversight of daily functions.',
    extra: 'Administrative functions are critical in various sectors, including government, business, education, and healthcare. Effective administration ensures the efficient functioning of organizations and the achievement of their goals.',
    tags: ['Management', 'Organization', 'Efficiency']
  },
  {
    heading: 'Politics',
    para: 'Politics encompasses the activities, processes, and principles associated with governance, public affairs, and the exercise of power within a society or nation. It involves decision-making, policy development, and the allocation of resources.',
    extra: 'Political systems can vary, including democracies, autocracies, and various forms of governance. Politics influences laws, regulations, and the distribution of benefits and responsibilities within a community. It is a central aspect of human societies.',
    tags: ['Governance', 'Policy', 'Power']
  },
  {
    heading: 'Pillage',
    para: 'Pillage is the act of forcefully taking or plundering valuable resources, possessions, or wealth, often through acts of theft, destruction, or violence. It is typically associated with wartime or lawless situations.',
    extra: 'Pillage can have devastating consequences for communities and regions affected by it. It has been a common practice in history during conflicts, invasions, and the breakdown of social order.',
    tags: ['Plunder', 'Conflict', 'Looting']
  },
  {
    heading: 'Innovation',
    para: 'Innovation refers to the process of creating, developing, and implementing new ideas, methods, products, or technologies that lead to positive change or improvement. It involves finding novel solutions to problems or challenges.',
    extra: 'Innovation can occur in various fields, including technology, business, science, and the arts. It is a driving force behind progress, economic growth, and the advancement of societies. Innovative thinking fosters creativity and drives evolution.',
    tags: ['Creativity', 'Change', 'Progress']
  },
  {
    heading: 'Nomads',
    para: 'Nomads are people or communities who lead a migratory or itinerant way of life, often moving from one place to another rather than residing in a fixed location. Nomadic cultures are characterized by their adaptability to changing environments and reliance on mobile livelihoods.',
    extra: 'Nomadic societies may include pastoralists who raise livestock, hunter-gatherers, and others who follow seasonal patterns of migration. They have historically played essential roles in trade, cultural exchange, and the exploration of new territories.',
    tags: ['Migratory Lifestyle', 'Cultural Adaptation', 'Nomadic Cultures']
  },  
  {
    heading: 'Alliance',
    para: 'An alliance is a formal or informal agreement or partnership between individuals, groups, organizations, or nations with shared interests or common goals. Alliances are often formed to achieve mutual benefits, enhance security, or address common challenges.',
    extra: 'Alliances can take various forms, including political, military, economic, and social alliances. They promote cooperation and collaboration among participants and can be important in maintaining stability and addressing global issues.',
    tags: ['Partnership', 'Cooperation', 'Common Goals']
  },
  {
    heading: 'Strategy',
    para: 'A strategy is a well-thought-out plan or approach designed to achieve specific goals, solve problems, or navigate complex situations. It involves the systematic allocation of resources and the consideration of various factors to attain a desired outcome.',
    extra: 'Strategies can be applied in diverse contexts, including business, military, sports, and personal life. Effective strategies often require careful analysis, decision-making, and adaptability to changing circumstances.',
    tags: ['Planning', 'Goals', 'Decision-Making']
  },
  {
    heading: 'Paganism',
    para: 'Paganism is a collective term for a diverse set of spiritual and religious beliefs and practices that are often rooted in pre-Abrahamic traditions. It can encompass polytheism, animism, nature worship, and the veneration of ancestors.',
    extra: 'Paganism has a long history and has been practiced by various cultures around the world. Contemporary Paganism includes a revival of ancient traditions and the development of new, nature-centered spiritual paths. It often emphasizes a deep connection to the natural world.',
    tags: ['Spirituality', 'Ancient Beliefs', 'Nature Worship']
  },
  {
    heading: 'Pagan',
    para: 'Pagan is a term historically used to describe individuals who follow polytheistic, non-Abrahamic religions or belief systems. It originally referred to rural, non-Christian, and non-Islamic communities and their religious practices.',
    extra: 'Paganism encompasses a wide range of beliefs, traditions, and cultures, often rooted in nature worship, animism, and the veneration of multiple deities. Today, some people identify as modern Pagans and practice contemporary Pagan religions that draw inspiration from ancient traditions.',
    tags: ['Religion', 'Polytheism', 'Spirituality']
  },
  {
    heading: 'Autocrat',
    para: 'An autocrat is a ruler or leader who holds absolute and centralized power, often with minimal or no checks and balances. Autocrats make decisions and exercise authority without significant input from others, and their rule can be authoritarian or dictatorial in nature.',
    extra: 'Autocracies can take various forms, including absolute monarchies and authoritarian regimes. Autocrats typically have significant control over government institutions, the military, and the judiciary, which can lead to limited political freedoms and civil liberties.',
    tags: ['Leadership', 'Absolute Power', 'Authoritarianism']
  },
  {
    heading: 'Aristocrat',
    para: 'An aristocrat is a member of a social class or elite group that is considered to be of high social rank, often due to hereditary privilege or nobility. Aristocrats historically held significant political, economic, and social influence in many societies.',
    extra: 'Aristocracy typically involves inherited titles, landownership, and a lifestyle associated with wealth and luxury. While traditional aristocracies have diminished in political power, the term is still used to describe individuals from prominent, privileged families.',
    tags: ['Social Class', 'Nobility', 'Privilege']
  },
  {
    heading: 'Latin',
    para: 'Latin refers to a classical language that originated in ancient Rome. It is the precursor to the Romance languages, such as Spanish, Italian, French, Portuguese, and Romanian, and has had a significant influence on the development of Western languages.',
    extra: 'Although Latin is no longer spoken as a native language, it continues to be used in scientific, religious, and academic contexts, and it remains an integral part of the cultural heritage of many countries.',
    tags: ['Language', 'Classical', 'Cultural Heritage']
  },
  {
    heading: 'Exotic',
    para: 'Exotic describes something that is foreign, unusual, or unfamiliar, often with a sense of fascination or attractiveness due to its uniqueness. It is a subjective term that can vary depending on one\'s cultural and personal perspective.',
    extra: 'Exotic items, places, or experiences are often characterized by their distinctiveness and the sense of adventure or curiosity they evoke. What is considered exotic can differ from person to person and from one culture to another.',
    tags: ['Unusual', 'Foreign', 'Uniqueness']
  },
  {
    heading: 'Euro-Asian',
    para: 'Euro-Asian, or Eurasian, refers to something or someone that is related to both Europe and Asia, which are the two largest continents on Earth. Eurasia is a landmass that encompasses both of these continents.',
    extra: 'Eurasia is known for its vast geographical and cultural diversity, and it includes regions like Russia, Turkey, and the Caucasus that straddle the boundary between Europe and Asia. The term "Euro-Asian" can describe anything or anyone with connections to this region.',
    tags: ['Geography', 'Cultural Diversity', 'Eurasia']
  },
  {
    heading: 'Hispanic',
    para: 'Hispanic refers to a person who has cultural or ancestral ties to Spain or Spanish-speaking countries, particularly those in Latin America. It encompasses people from various ethnic backgrounds who share the Spanish language and cultural influences.',
    extra: 'The term "Hispanic" is often used in the United States and other countries to categorize individuals of Spanish-speaking descent. It is a broad and inclusive term that recognizes the diversity of Spanish-speaking communities worldwide.',
    tags: ['Culture', 'Latin America', 'Language']
  },
  {
    heading: 'Castle',
    para: 'A castle is a fortified and often grandiose structure, typically constructed with thick walls, towers, and defensive features. Castles were historically built for military defense and served as strongholds for nobility and royalty.',
    extra: 'Castles were common in medieval Europe and other parts of the world. They featured elements such as drawbridges, moats, battlements, and arrow slits to protect against attacks. Over time, some castles evolved into symbols of power and authority and were also used for residential purposes.',
    tags: ['Architecture', 'Medieval History', 'Fortification']
  },
  {
    heading: 'Stronghold',
    para: 'A stronghold is a fortified place or location, often a castle, fortress, or citadel, designed to provide protection and serve as a defensive center. Strongholds are strategically positioned to control territory and repel attacks.',
    extra: 'Strongholds have been used throughout history for military purposes, as well as for maintaining control over regions and safeguarding valuable assets. They are characterized by their robust construction and defensive features.',
    tags: ['Fortification', 'Defense', 'Military Strategy']
  },
  {
    heading: 'Grotto',
    para: 'A grotto is a natural or artificially constructed cave or cavern-like structure, often located in a garden, park, or scenic area. Grottos can be characterized by their rock formations, stalactites, and stalagmites, and they are typically designed for aesthetic or recreational purposes.',
    extra: 'In architectural and landscape design, grottos are often adorned with sculptures, fountains, water features, and vegetation to create a serene and visually appealing environment. They have historical and cultural significance in various societies, including ancient Roman and Renaissance art and architecture.',
    tags: ['Landscape Design', 'Cave Structure', 'Aesthetics']
  },
  {
    heading: 'Parade',
    para: 'A parade is a public procession or event in which people, vehicles, and sometimes animals move in an organized and often celebratory manner through a designated route or area. Parades are typically held to mark special occasions, festivals, holidays, or commemorate significant events.',
    extra: 'Parades often feature a variety of elements, including marching bands, floats, dancers, costumed participants, and displays of cultural or historical significance. They serve as a form of entertainment, cultural expression, and community celebration.',
    tags: ['Celebration', 'Cultural Event', 'Procession']
  },
  {
    heading: 'History',
    para: 'History is the systematic study and record of past events, experiences, and human activities. It encompasses the exploration and analysis of events, people, cultures, and societies from earlier periods, with the aim of understanding the development of the past.',
    extra: 'Historians use various sources, including written records, oral traditions, archaeological findings, and artifacts, to reconstruct and interpret history. It plays a vital role in understanding the evolution of human civilizations and provides insights into the present and future.',
    tags: ['Historical Studies', 'Past Events', 'Cultural Evolution']
  },
  {
    heading: 'Burhs',
    para: 'Burhs were fortified towns or settlements established in Anglo-Saxon England during the 9th and 10th centuries. They served as defensive structures and centers of administration, particularly during the Viking Age when England faced frequent raids and invasions.',
    extra: 'The construction of burhs was a part of King Alfred the Great's defensive strategy to protect England from Viking incursions. These fortified towns often had walls, gates, and a garrison of soldiers. They played a significant role in the defense of the realm and were an important feature of the Anglo-Saxon period.',
    tags: ['Anglo-Saxon', 'Medieval History', 'Defensive Fortifications']
  },
  {
    heading: 'Hindrance',
    para: 'A hindrance is an obstacle, impediment, or barrier that interferes with or delays progress, development, or the completion of a task or goal. It represents something that hampers or obstructs one's efforts or intentions.',
    extra: 'Hindrances can take various forms, such as physical obstacles, bureaucratic red tape, personal challenges, or external factors. Overcoming hindrances often requires problem-solving, determination, and adaptability.',
    tags: ['Obstacle', 'Impediment', 'Challenges']
  },
  {
    heading: 'Anglo-Saxon',
    para: 'Anglo-Saxon refers to a historical period and people who lived in England from the early 5th century to the Norman Conquest in 1066. The term also denotes the Germanic tribes, including the Angles, Saxons, and Jutes, who migrated to and settled in England during this era.',
    extra: 'The Anglo-Saxon period is characterized by the development of the English language, culture, and governance. It saw the rise of various kingdoms and the eventual unification of England. The era left a lasting impact on English history and language.',
    tags: ['History', 'Medieval England', 'Germanic Tribes']
  },
  {
    heading: 'Anxious',
    para: 'Anxious is an adjective that describes a state of uneasiness, worry, or apprehension. It is characterized by heightened nervousness and a sense of impending danger or uncertainty.',
    extra: 'Anxiety is a common human emotion and can range from mild to severe. Chronic or excessive anxiety can negatively impact mental and physical health and may require professional intervention and treatment.',
    tags: ['Emotions', 'Mental Health', 'Worry']
  },
  {
    heading: 'Unwind',
    para: 'To unwind means to relax, de-stress, or release tension and anxiety. It involves taking a break from work, responsibilities, or daily routines to engage in activities or practices that promote relaxation and a sense of calm.',
    extra: 'Ways to unwind may include leisure activities like reading, listening to music, practicing mindfulness, or spending time in nature. Unwinding is essential for mental and emotional well-being.',
    tags: ['Relaxation', 'Stress Relief', 'Mental Health']
  },
  {
    heading: 'Government',
    para: 'A government is the system or body that exercises political authority and control over a geographic region, state, or nation. It is responsible for making and enforcing laws, providing public services, and representing the interests of its citizens.',
    extra: 'Governments can take various forms, including democracies, monarchies, republics, and authoritarian regimes. The structure and functions of a government are defined by its constitution and legal framework.',
    tags: ['Politics', 'Authority', 'Public Administration']
  },
  {
    heading: 'Governance',
    para: 'Governance refers to the process and structure by which a group, organization, or entity is directed, controlled, and administered. It encompasses the mechanisms, policies, and practices that guide decision-making and ensure accountability and responsibility.',
    extra: 'Good governance is characterized by transparency, accountability, participation, and the rule of law. It is essential in various contexts, including corporate governance, public governance, and international organizations.',
    tags: ['Management', 'Accountability', 'Decision-Making']
  },
  {
    heading: 'Polis',
    para: 'A polis is a term used in ancient Greece to refer to a city-state, which was a self-governing urban center and its surrounding territory. Each polis had its own government, laws, and often a unique cultural identity.',
    extra: 'The concept of the polis was central to ancient Greek political and social life, and it played a significant role in the development of democratic governance. Well-known Greek city-states include Athens, Sparta, and Thebes.',
    tags: ['Ancient Greece', 'City-State', 'Self-Governance']
  },
  {
    heading: 'Monarch',
    para: 'A monarch is an individual who holds the highest authority in a monarchy and serves as the head of state. Monarchs may have various titles, such as king, queen, emperor, or empress, depending on their gender and the specific monarchy.',
    extra: 'The role and powers of a monarch can vary widely depending on the type of monarchy, from absolute authority to ceremonial and symbolic roles in constitutional monarchies. Monarchs often play a significant role in the history and culture of their respective nations.',
    tags: ['Head of State', 'Royalty', 'Leadership']
  },
  {
    heading: 'Monarchy',
    para: 'A monarchy is a form of government where a single individual, known as a monarch, holds supreme authority and serves as the head of state. Monarchies can be hereditary, where leadership is passed down within a royal family, or elective.',
    extra: 'Monarchies have existed throughout history and can take various forms, including absolute monarchies, constitutional monarchies, and elective monarchies. The monarch's powers and role may vary depending on the specific system in place.',
    tags: ['Government', 'Royalty', 'Hereditary Rule']
  },
  {
    heading: 'Sovereign',
    para: 'Sovereign is an adjective that describes a state or entity that possesses full and independent authority over its territory and governance. It implies a supreme and autonomous status, free from external control or interference.',
    extra: 'Sovereign states have the power to make their own laws, decisions, and foreign policy without being subordinate to another authority. The term is essential in international relations and the recognition of nations.',
    tags: ['Statehood', 'Independence', 'Autonomy']
  },
  {
    heading: 'Reign',
    para: 'Reign refers to the period during which a monarch or ruler holds power and governs a state or kingdom. It encompasses the duration of a monarch's rule and is often associated with their influence and authority over a particular region.',
    extra: 'Reigns can vary in length and significance, and they are often marked by historical events and political developments. The term is commonly used in the context of monarchies and historical accounts of leadership.',
    tags: ['Monarchy', 'Rule', 'Political Authority']
  },
  {
    heading: 'Siege',
    para: 'A siege is a military strategy in which an army or force surrounds and isolates a fortified location, such as a city, with the intention of cutting off supplies and forcing surrender. Sieges can last for an extended period and often involve both offensive and defensive tactics.',
    extra: 'Historically, sieges have been employed in various conflicts and wars to capture or defend important strategic positions. They require careful planning and the use of siege engines and tactics to breach fortifications.',
    tags: ['Military Strategy', 'Fortification', 'Blockade']
  },
  {
    heading: 'Holy Grail',
    para: 'The Holy Grail is a legendary and sacred object in various mythologies and medieval legends, most notably associated with the Christian tradition. It is often depicted as a chalice or dish used by Jesus Christ during the Last Supper and later said to possess mystical and divine properties.',
    extra: 'The quest for the Holy Grail has been a recurring theme in literature, art, and folklore. It represents the pursuit of a noble and often unattainable goal, embodying themes of faith, purity, and spiritual enlightenment.',
    tags: ['Mythology', 'Legend', 'Quest']
  },
  {
    heading: 'Viscosity',
    para: 'Viscosity is a physical property of a fluid that measures its resistance to flow. It refers to the thickness or stickiness of a fluid, and it can vary from low viscosity (thin, easily flowing) to high viscosity (thick, resistant to flow).',
    extra: 'Viscosity plays a crucial role in various applications, including the automotive industry (engine lubricants), food industry (sauces and liquids), and pharmaceuticals (medicine formulations). It is typically measured in units such as poise or pascal-seconds (Pa·s).',
    tags: ['Physics', 'Fluid Mechanics', 'Resistance to Flow']
  },
  {
    heading: 'Strong',
    para: 'Strong is an adjective that describes having a high degree of physical, mental, or emotional strength and resilience. It signifies the ability to endure challenges, exert force, or maintain a robust state of well-being.',
    extra: 'Strength can manifest in different ways, such as physical strength, mental fortitude, or emotional stability. Building and maintaining strength often involve physical exercise, mental training, and emotional self-care.',
    tags: ['Strength', 'Resilience', 'Well-being']
  },
  {
    heading: 'Weak',
    para: 'Weak is an adjective used to describe a lack of physical or mental strength, power, or resilience. It can refer to an individual's physical condition, character, or abilities, indicating a vulnerability or inability to withstand challenges or exert force.',
    extra: 'In various contexts, weakness can be temporary or chronic, and it may apply to physical health, emotional state, or moral character. Overcoming weakness often involves building strength, resilience, or seeking support.',
    tags: ['Strength', 'Vulnerability', 'Resilience']
  },
  {
    heading: 'War',
    para: 'War is a state of organized and often armed conflict between different nations, groups, or entities. It typically involves large-scale hostilities, such as battles and military operations, and can have far-reaching consequences, including loss of life, destruction, and political and social upheaval.',
    extra: 'Throughout history, wars have been waged for various reasons, including territorial disputes, ideological differences, and resources. Efforts to prevent and resolve conflicts and promote peace are essential in the modern world.',
    tags: ['Conflict', 'Military', 'Peace']
  },
  {
    heading: 'Sympathy',
    para: 'Sympathy refers to the feelings of pity, sorrow, or compassion that one person may experience in response to another person's suffering or misfortune. It involves recognizing another's distress without necessarily sharing the same emotions or experiences.',
    extra: 'While sympathy shows a sense of caring and support, it may not involve the same level of emotional connection as empathy. Sympathetic individuals express concern and may offer comfort or assistance to those in need.',
    tags: ['Compassion', 'Support', 'Empathy vs. Sympathy']
  },
  {
    heading: 'Empathy',
    para: 'Empathy is the ability to understand and share the feelings, thoughts, and experiences of another person. It involves not only recognizing someone else's emotions but also being able to emotionally connect and show genuine concern and support.',
    extra: 'Empathy is considered a fundamental aspect of human social interaction and is often associated with increased understanding, compassion, and the ability to build strong interpersonal relationships. It plays a crucial role in fields such as psychology, counseling, and healthcare.',
    tags: ['Emotions', 'Interpersonal Relationships', 'Compassion']
  },
  {
    heading: 'Psychology',
    para: 'Psychology is the scientific study of the human mind and behavior. It seeks to understand and explain various aspects of mental processes, emotions, cognition, and behavior through systematic research, observation, and analysis.',
    extra: 'Psychology encompasses various subfields, including clinical psychology, cognitive psychology, social psychology, and developmental psychology. It is applied in areas such as therapy, counseling, education, and organizational behavior.',
    tags: ['Science', 'Mental Processes', 'Behavioral Science']
  },
  {
    heading: 'Trait',
    para: 'A trait is a distinct characteristic or feature that can be observed in an individual's behavior, personality, or physical attributes. Traits are inherent qualities that contribute to an individual's uniqueness and are often influenced by genetic, environmental, and cultural factors.',
    extra: 'In the field of psychology, traits are used to describe and study personality differences among individuals. Traits can be categorized as either personality traits, which relate to enduring patterns of behavior, or physical traits, which pertain to an individual's physical appearance and genetic makeup.',
    tags: ['Psychology', 'Personality', 'Characteristics']
  },
  {
    heading: 'Strait',
    para: 'A strait is a narrow waterway or passage that connects two larger bodies of water, such as seas or oceans, and often serves as a natural channel for maritime navigation. Straits are typically characterized by their restricted width, which can create challenges for ships and vessels to navigate.',
    extra: 'Straits can be strategically important for international trade and transportation, and they often have historical and geopolitical significance. Examples of well-known straits include the Strait of Gibraltar, the Bosphorus Strait, and the Strait of Malacca.',
    tags: ['Geography', 'Maritime Navigation', 'Waterway']
  },
  {
    heading: 'Pomodoro Technique',
    para: 'The Pomodoro Technique is a time management method developed by Francesco Cirillo in the late 1980s. It involves breaking work or tasks into intervals, traditionally 25 minutes in length, separated by short breaks. These intervals are referred to as "Pomodoros."',
    extra: 'The technique is designed to improve productivity and focus by encouraging individuals to work in short, focused bursts and then take regular breaks. It is named after the Italian word for "tomato" because Cirillo initially used a tomato-shaped kitchen timer to track his work intervals.',
    tags: ['Time Management', 'Productivity', 'Work Technique']
  },
  {
    heading: 'Promo',
    para: 'A promo is a shortened form of the word "promotion" and refers to a marketing or advertising tactic used to promote a product, service, event, or brand. Promos are designed to attract and engage customers, often by offering discounts, incentives, or special offers.',
    extra: 'Promos can take various forms, including advertisements, coupons, contests, and giveaways. They are a common strategy used by businesses and organizations to increase awareness, drive sales, and build customer loyalty.',
    tags: ['Marketing', 'Advertising', 'Promotion Strategy']
  },
  {
    heading: 'Prom',
    para: 'A prom, short for "promenade," is a formal or semi-formal event typically held at the end of the high school academic year. It is a special social gathering where students dress elegantly, often in formal attire, and come together to celebrate and dance.',
    extra: 'Proms are a significant cultural tradition in many countries, especially in the United States, and often include activities like dancing, music, the crowning of a prom king and queen, and the exchange of prom favors or keepsakes.',
    tags: ['High School', 'Formal Event', 'Social Tradition']
  },
  {
    heading: 'Buoyancy',
    para: 'Buoyancy is a physical property of fluids, such as water or air, that describes the upward force exerted by a fluid on an object submerged in it. This force opposes the weight of the object and causes it to float or rise in the fluid.',
    extra: 'Archimedes' principle, named after the ancient Greek scientist Archimedes, explains buoyancy and states that the buoyant force is equal to the weight of the displaced fluid. Buoyancy plays a crucial role in various fields, including ship design, aviation, and underwater exploration.',
    tags: ['Physics', 'Fluid Mechanics', 'Archimedes' Principle']
  },
  {
    heading: 'Archipelago',
    para: 'An archipelago is a geographical term that refers to a group or chain of islands that are closely spaced and often surrounded by a body of water, such as the sea or an ocean. Archipelagos can vary in size, from small clusters of islands to vast island chains.',
    extra: 'Some well-known archipelagos include the Hawaiian Islands in the Pacific Ocean, the Maldives in the Indian Ocean, and the Greek Islands in the Mediterranean Sea.',
    tags: ['Geography', 'Islands', 'Oceanography']
  },
  {
    heading: 'Narcotics',
    para: 'Narcotics are a category of drugs that primarily include substances derived from opium poppy plants, such as heroin, morphine, and codeine. These drugs have strong pain-relieving properties and are often used for medical purposes, but they can also have a high potential for abuse and addiction.',
    extra: 'The term "narcotics" is sometimes used more broadly to refer to any illegal or controlled substances, including not only opiate-based drugs but also cocaine, marijuana, and synthetic drugs.',
    tags: ['Drugs', 'Opioids', 'Addiction']
  },
  {
    heading: 'Narcissism',
    para: 'Narcissism is a psychological term that refers to a personality trait or disorder characterized by an excessive focus on oneself, one's appearance, abilities, or achievements, often accompanied by a lack of empathy for others and a constant need for admiration and validation.',
    extra: 'Narcissism can range from a healthy level of self-confidence and self-esteem to pathological narcissism, such as narcissistic personality disorder (NPD), which is a more severe and rigid condition.',
    tags: ['Psychology', 'Personality Trait', 'Narcissistic Personality Disorder']
  },
  {
    heading: 'Narcissist',
    para: 'A narcissist is an individual who displays excessive self-love, self-importance, and an exaggerated sense of their own abilities and achievements. They often lack empathy for others and seek constant admiration and validation from those around them.',
    extra: 'Narcissistic personality disorder (NPD) is a psychological condition characterized by a pervasive pattern of narcissistic behavior and a profound need for attention and admiration.',
    tags: ['Psychology', 'Personality Disorder', 'Narcissism']
  },
  // Add more headings as needed
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