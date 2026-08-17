const CATEGORIES = ['Kitchen', 'Outdoor', 'Desk', 'Lighting', 'Storage', 'Textiles'];
const ADJECTIVES = ['Copper', 'Matte', 'Folding', 'Linen', 'Walnut', 'Slate', 'Brushed', 'Woven'];
const NOUNS = ['Kettle', 'Lamp', 'Crate', 'Throw', 'Stool', 'Planter', 'Tray', 'Organiser'];

// Pseudo-random number generator based on ID
function mulberry32(a) {
    return function() {
      var t = a += 0x6D2B79F5;
      t = Math.imul(t ^ t >>> 15, t | 1);
      t ^= t + Math.imul(t ^ t >>> 7, t | 61);
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    }
}

const PRODUCT_IMAGES = {
    'Kettle': [
        'https://images.unsplash.com/photo-1544787219-7f47ccb76574?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1594212699903-ec8a3eca50f6?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1576092768241-dec231879fc3?auto=format&fit=crop&w=800&q=80'
    ],
    'Lamp': [
        'https://images.unsplash.com/photo-1507473885765-e6ed057f782c?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1513506003901-1e6a229e2d15?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1540932239986-30128078f3c5?auto=format&fit=crop&w=800&q=80'
    ],
    'Crate': [
        'https://images.unsplash.com/photo-1595246140625-573b715d11dc?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1589939705384-5185137a7f0f?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1601004890684-d8cbf643f5f2?auto=format&fit=crop&w=800&q=80'
    ],
    'Throw': [
        'https://images.unsplash.com/photo-1584100936595-c0654b55a2e2?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1600121848594-d8644e57abab?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1517841905240-472988babdf9?auto=format&fit=crop&w=800&q=80'
    ],
    'Stool': [
        'https://images.unsplash.com/photo-1503602642458-232111445657?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1586023492125-27b2c045efd7?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1555041469-a586c61ea9bc?auto=format&fit=crop&w=800&q=80'
    ],
    'Planter': [
        'https://images.unsplash.com/photo-1485955900006-10f4d324d411?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1416879595882-3373a0480b5b?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1512428559087-560fa5ceab42?auto=format&fit=crop&w=800&q=80'
    ],
    'Tray': [
        'https://images.unsplash.com/photo-1530018607912-eff2daa1bac4?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1615397349754-cfa2066a298e?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1578749556568-bc2c40e68b61?auto=format&fit=crop&w=800&q=80'
    ],
    'Organiser': [
        'https://images.unsplash.com/photo-1544816155-12df9643f363?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1585336261026-875a60a1c96b?auto=format&fit=crop&w=800&q=80',
        'https://images.unsplash.com/photo-1506784983877-45594efa4cbe?auto=format&fit=crop&w=800&q=80'
    ]
};

function makeProduct(id) {
    const random = mulberry32(id);
    const catIdx = Math.floor(random() * CATEGORIES.length);
    const adjIdx = Math.floor(random() * ADJECTIVES.length);
    const nounIdx = Math.floor(random() * NOUNS.length);
    const noun = NOUNS[nounIdx];
    
    // Deterministic hue for CSS gradient fallback image
    const hue1 = Math.floor(random() * 360);
    const hue2 = (hue1 + 40) % 360;

    const images = PRODUCT_IMAGES[noun] || PRODUCT_IMAGES['Lamp'];
    const imgIdx = Math.floor(random() * images.length);

    return {
        id: id,
        name: `${ADJECTIVES[adjIdx]} ${noun}`,
        category: CATEGORIES[catIdx],
        price: (random() * 150 + 10).toFixed(2),
        rating: (random() * 2 + 3).toFixed(1),
        stock: Math.floor(random() * 100),
        description: `A beautifully crafted ${ADJECTIVES[adjIdx].toLowerCase()} ${noun.toLowerCase()} for your ${CATEGORIES[catIdx].toLowerCase()} needs.`,
        gradient: `linear-gradient(135deg, hsl(${hue1}, 20%, 85%), hsl(${hue2}, 20%, 75%))`,
        image: images[imgIdx]
    };
}

const PRODUCTS = Array.from({length: 600}, (_, i) => makeProduct(8801 + i));
window.PRODUCTS = PRODUCTS;

function getProductById(id) {
    return PRODUCTS.find(p => p.id === id);
}

function getProductsPage(page, perPage = 12) {
    const start = (page - 1) * perPage;
    return PRODUCTS.slice(start, start + perPage);
}
