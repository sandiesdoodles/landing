/**
 * Sandies Doodles — live litter content.
 * Swap pups / pricing / status as the litter advances.
 */
window.SANDIES = {
  brand: "Sandies Doodles",
  tagline: "Family-raised Goldendoodles in Hobe Sound, Florida",
  status: {
    mode: "live",
    headline: "Abby’s Litter 2 — meet the puppies",
    note: "8 named pups · 5 girls · 3 boys. Early list open for reservation updates.",
  },
  hero: {
    headline: "Abby’s Litter 2 is here.",
    support:
      "Cypress, Oakley, Delilah, Violet, Cedar, Ginger, Lotus, and Meadow — eight family-raised F2 Goldendoodles growing at home in Hobe Sound.",
  },
  heroSecondary: {
    label: "Meet the puppies",
    href: "#litter",
  },
  currentLitter: {
    title: "Current litter",
    eyebrow: "Abby × Oliver · F2 Goldendoodles",
    headline: "8 puppies · 5 girls · 3 boys",
    blurb:
      "Individual profiles are live. Join the early list — deposits open next for approved families.",
    girls: ["Delilah", "Violet", "Ginger", "Lotus", "Meadow"],
    boys: ["Cypress", "Oakley", "Cedar"],
    image: "assets/pups/litter2/group.jpg",
    imageAlt: "Abby’s Litter 2 puppies napping together",
    ctaLabel: "Join early list",
    ctaHref: "#waitlist",
  },
  formspree: "https://formspree.io/f/xykpbwkg",
  contact: {
    email: "SandiesDoodles1@gmail.com",
    phone: "(772) 530-7433",
    phoneHref: "tel:+17725307433",
    location: "Hobe Sound, Florida",
    facebook: "https://www.facebook.com/SandiesDoodles",
  },
  parents: [
    {
      id: "abby",
      name: "Abby",
      role: "Dam",
      weight: "22 lb",
      image: "assets/parents/abby.png",
      blurb:
        "Cream-white teddy face. Gentle, cuddly, and people-focused — the calm heart of the program.",
    },
    {
      id: "oliver",
      name: "Oliver",
      role: "Sire",
      weight: "44 lb",
      image: "assets/parents/oliver.png",
      blurb:
        "Warm caramel waves. Confident, friendly, and playful — our stud and steady counterpart.",
    },
  ],
  genetics: {
    generation: "F2 Goldendoodles",
    generationNote:
      "Both parents are Goldendoodles (Goldendoodle × Goldendoodle = F2). Coat and shed can vary; we do not currently produce F1B.",
    adultSize: "About 30–40 lb at maturity (based on 22 lb mom / 44 lb dad)",
  },
  pricing: {
    label: "Litter 2 pricing starts at $2,400. Join the early list.",
    base: 2400,
    deposit: 500,
    currency: "USD",
    depositTiming: "Deposits are not open yet — early list first.",
    includes: [
      "Wellness exam + certificate of veterinary inspection before go-home",
      "Age-appropriate vaccines & deworming log",
      "Starter food sample + mom-scent item",
      "Written bill of sale + care packet",
      "Two weeks of text support after pickup",
    ],
    tiers: [],
  },
  transport: {
    title: "Reservations & transport",
    intro:
      "Local pickup in Hobe Sound is preferred. Buyer-paid transport may be available for approved families after deposits open.",
    rules: [
      "No puppy leaves before 8 weeks old",
      "Veterinary clearance + required health paperwork",
      "Full payment cleared before pickup or transport",
      "Transport costs are separate from the puppy price",
    ],
    options: [
      { name: "Local pickup", note: "Preferred · free" },
      { name: "Meet-up delivery", note: "Case by case · fee by distance" },
      { name: "Approved ground transporter", note: "Buyer pays transporter" },
      { name: "Approved flight nanny", note: "Buyer arranges after approval" },
    ],
  },
  process: [
    {
      step: "01",
      title: "Join the early list",
      text: "Fill out the interest form. We approve families before deposits open.",
    },
    {
      step: "02",
      title: "Reserve with a deposit",
      text: "$500 holds your place once deposits open for approved families.",
    },
    {
      step: "03",
      title: "Weekly updates",
      text: "Photos, growth notes, and temperament while they grow at home with us.",
    },
    {
      step: "04",
      title: "Go-home day",
      text: "8+ weeks, vet clearance, paperwork, full payment — then pickup or approved transport.",
    },
  ],
  faqs: [
    {
      q: "What generation are the puppies?",
      a: "F2 Goldendoodles — both Abby and Oliver are Goldendoodles. We explain coat expectations clearly before any deposit.",
    },
    {
      q: "How big will they get?",
      a: "Most land around 30–40 lb as adults, based on Abby (22 lb) and Oliver (44 lb).",
    },
    {
      q: "When can a puppy go home?",
      a: "Not before 8 weeks. Every puppy leaves only after veterinary clearance, required health paperwork, and full payment.",
    },
    {
      q: "Do you offer transport?",
      a: "Local pickup in Hobe Sound is preferred. Buyer-paid options may be available for approved families: meet-up delivery, approved ground transporter, or flight nanny. Transport costs are separate from the puppy price.",
    },
    {
      q: "Are they AKC registered?",
      a: "Goldendoodles are not AKC-recognized as a purebred. We focus on health, temperament, and honest lineage notes.",
    },
    {
      q: "What does the deposit cover?",
      a: "A $500 deposit reserves your place and applies to the final price. It is non-refundable if you back out; refundable or transferable if we cannot provide a puppy for health or breeder reasons. Written agreement required before payment.",
    },
    {
      q: "When do deposits open?",
      a: "Profiles and pricing are up now. Deposits open next for approved families on the early list.",
    },
    {
      q: "How much do the puppies cost?",
      a: "Litter 2 pricing starts at $2,400. Exact puppy and any pick options are confirmed before a deposit is requested.",
    },
    {
      q: "What health steps do puppies get?",
      a: "Age-appropriate deworming, vaccine window, wellness exam, and certificate of veterinary inspection before go-home. You’ll receive a care packet and health log.",
    },
  ],
  testimonials: [
    {
      quote:
        "Clear updates the whole way and a calm go-home day. Our pup settled in like they’d always been ours.",
      name: "Litter 1 family",
      place: "South Florida",
    },
    {
      quote:
        "You can tell these dogs are raised in a real home. Temperament was exactly what we hoped for.",
      name: "Litter 1 family",
      place: "Treasure Coast",
    },
    {
      quote:
        "Paperwork, starter kit, and support after pickup made the first week easy. We’ll be back.",
      name: "Litter 1 family",
      place: "Florida",
    },
  ],
  alumniNote:
    "Litter 1 puppies below are all placed — shared as a look at the dogs we raise.",
  litter2: [
    {
      id: "cypress",
      name: "Cypress",
      sex: "Male",
      collar: "Lime",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/cypress.jpg?v=cards0924",
      status: "available",
      blurb:
        "Warm apricot curls, pale muzzle, and a confident little stare.",
    },
    {
      id: "oakley",
      name: "Oakley",
      sex: "Male",
      collar: "Grey / blaze",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/oakley.jpg?v=cards0924",
      status: "available",
      blurb:
        "White forehead blaze, warm curls, and a soft, steady look.",
    },
    {
      id: "delilah",
      name: "Delilah",
      sex: "Female",
      collar: "Blue / cyan",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/delilah.jpg?v=cards0924",
      status: "available",
      blurb:
        "Soft apricot curls and a calm, sweet little face.",
    },
    {
      id: "violet",
      name: "Violet",
      sex: "Female",
      collar: "Purple",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/violet.jpg?v=cards0924",
      status: "available",
      blurb:
        "Warm apricot curls with a gentle, affectionate look.",
    },
    {
      id: "cedar",
      name: "Cedar",
      sex: "Male",
      collar: "Dark grey / black",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/cedar.jpg?v=cards0924",
      status: "available",
      blurb:
        "Calm apricot curls with a soft white snout.",
    },
    {
      id: "ginger",
      name: "Ginger",
      sex: "Female",
      collar: "Red",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/ginger.jpg?v=cards0924",
      status: "available",
      blurb:
        "Warm apricot curls with bright eyes and a playful spark.",
    },
    {
      id: "lotus",
      name: "Lotus",
      sex: "Female",
      collar: "Yellow",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/lotus.jpg?v=cards0924",
      status: "available",
      blurb:
        "Warm apricot curls, cream muzzle, and a soft curious head tilt.",
    },
    {
      id: "meadow",
      name: "Meadow",
      sex: "Female",
      collar: "Pink",
      size: "~30–40 lb adult estimate",
      image: "assets/pups/litter2/meadow.jpg?v=cards0924",
      status: "available",
      blurb:
        "Warm apricot curls and a calm, grounded little face.",
    },
  ],
  pups: [
    {
      id: "cosmos",
      name: "Cosmos",
      sex: "Male",
      collar: "Blue",
      size: "~32–44 lb adult estimate",
      image: "assets/pups/cosmos.jpg",
      status: "placed",
      blurb:
        "Warm apricot curls, white chest patch, calm-curious explorer energy. Our little gentleman.",
    },
    {
      id: "willow",
      name: "Willow",
      sex: "Female",
      collar: "—",
      size: "~30–42 lb adult estimate",
      image: "assets/pups/willow.jpg",
      status: "placed",
      blurb:
        "Soft apricot with white chest and toes. Steady, tender, and deeply people-focused.",
    },
    {
      id: "jasper",
      name: "Jasper",
      sex: "Male",
      collar: "—",
      size: "~28–40 lb adult estimate",
      image: "assets/pups/jasper.jpg",
      status: "placed",
      blurb:
        "Handsome apricot boy with balance — playful without chaos, affectionate without cling.",
    },
    {
      id: "lilly",
      name: "Lilly",
      sex: "Female",
      collar: "—",
      size: "~22–34 lb adult estimate",
      image: "assets/pups/lilly.jpg",
      status: "placed",
      blurb:
        "Creamy-apricot teddy. Gentle cuddle bug who may stay on the smaller side of medium.",
    },
    {
      id: "ivy",
      name: "Ivy",
      sex: "Female",
      collar: "Red",
      size: "~27–38 lb adult estimate",
      image: "assets/pups/ivy.jpg",
      status: "placed",
      blurb:
        "Apricot girl with white sock toes. Sweet, bright-eyed, and built for lap-time connection.",
    },
  ],
};
