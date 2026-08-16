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

function makeProduct(id) {
    const random = mulberry32(id);
    const catIdx = Math.floor(random() * CATEGORIES.length);
    const adjIdx = Math.floor(random() * ADJECTIVES.length);
    const nounIdx = Math.floor(random() * NOUNS.length);
    
    // Deterministic hue for CSS gradient image
    const hue1 = Math.floor(random() * 360);
    const hue2 = (hue1 + 40) % 360;

    return {
        id: id,
        name: `${ADJECTIVES[adjIdx]} ${NOUNS[nounIdx]}`,
        category: CATEGORIES[catIdx],
        price: (random() * 150 + 10).toFixed(2),
        rating: (random() * 2 + 3).toFixed(1),
        stock: Math.floor(random() * 100),
        description: `A beautifully crafted ${ADJECTIVES[adjIdx].toLowerCase()} ${NOUNS[nounIdx].toLowerCase()} for your ${CATEGORIES[catIdx].toLowerCase()} needs.`,
        gradient: `linear-gradient(135deg, hsl(${hue1}, 20%, 85%), hsl(${hue2}, 20%, 75%))`
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
