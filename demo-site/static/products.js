// Product images are served from static/img/ so the store renders with
// networking disabled. Do not reintroduce remote image URLs: the demo is
// meant to run entirely offline, and an external request on every product
// page breaks that guarantee.
const REAL_PRODUCTS = [
    {
        id: 8801,
        name: "Wireless Bluetooth Headphones",
        category: "ELECTRONICS",
        price: 2499,
        rating: 4.7,
        stock: 45,
        description: "High-fidelity wireless over-ear headphones with active noise cancellation and 30-hour battery life.",
        image: "static/img/p01.jpg"
    },
    {
        id: 8802,
        name: "Mechanical Gaming Keyboard",
        category: "ELECTRONICS",
        price: 3299,
        rating: 4.8,
        stock: 30,
        description: "RGB tactile mechanical keyboard with custom hot-swappable switches and ergonomic wrist rest.",
        image: "static/img/p02.jpg"
    },
    {
        id: 8803,
        name: "Ergonomic Wireless Mouse",
        category: "ELECTRONICS",
        price: 699,
        rating: 4.5,
        stock: 80,
        description: "Precision 2.4GHz wireless optical mouse with ergonomic grip and silent click switches.",
        image: "static/img/p03.jpg"
    },
    {
        id: 8804,
        name: "Wireless Noise-Canceling Earbuds",
        category: "ELECTRONICS",
        price: 1799,
        rating: 4.6,
        stock: 65,
        description: "Compact true wireless earbuds with deep bass, IPX5 water resistance, and wireless charging case.",
        image: "static/img/p04.jpg"
    },
    {
        id: 8805,
        name: "Portable Bluetooth Speaker",
        category: "ELECTRONICS",
        price: 1599,
        rating: 4.4,
        stock: 50,
        description: "Rugged waterproof portable speaker with 360-degree room-filling sound and 12-hour playtime.",
        image: "static/img/p05.jpg"
    },
    {
        id: 8806,
        name: "20,000mAh Fast Charging Power Bank",
        category: "ELECTRONICS",
        price: 1299,
        rating: 4.7,
        stock: 90,
        description: "High-capacity power bank with 22.5W fast charging support and dual USB-C/USB-A output ports.",
        image: ""
    },
    {
        id: 8807,
        name: "Smartwatch with Fitness Tracker",
        category: "ELECTRONICS",
        price: 2999,
        rating: 4.5,
        stock: 40,
        description: "Feature-rich smartwatch with heart rate monitor, SpO2 sensor, sleep tracking, and AMOLED display.",
        image: "static/img/p07.jpg"
    },
    {
        id: 8808,
        name: "External 1TB Portable SSD",
        category: "ELECTRONICS",
        price: 5999,
        rating: 4.9,
        stock: 25,
        description: "Ultra-fast 1050MB/s USB 3.2 Gen 2 portable solid-state drive with shock-resistant aluminum casing.",
        image: "static/img/p08.jpg"
    },
    {
        id: 8809,
        name: "Smart LED Desk Lamp",
        category: "HOME & OFFICE",
        price: 1099,
        rating: 4.6,
        stock: 60,
        description: "Dimmable LED desk lamp with touch control, adjustable color temperature, and built-in USB charger.",
        image: "static/img/p09.jpg"
    },
    {
        id: 8810,
        name: "Stainless Steel Water Bottle",
        category: "HOME & KITCHEN",
        price: 799,
        rating: 4.8,
        stock: 120,
        description: "Double-wall vacuum insulated flask keeping drinks cold for 24 hours or hot for 12 hours.",
        image: "static/img/p10.jpg"
    },
    {
        id: 8811,
        name: "Ceramic Artisan Coffee Mug",
        category: "HOME & KITCHEN",
        price: 399,
        rating: 4.5,
        stock: 85,
        description: "Handcrafted 350ml ceramic coffee mug with comfortable handle and smooth matte glaze finish.",
        image: "static/img/p11.jpg"
    },
    {
        id: 8812,
        name: "Electric Gooseneck Water Kettle",
        category: "HOME & KITCHEN",
        price: 2199,
        rating: 4.7,
        stock: 35,
        description: "Precision pour-over electric kettle with rapid boiling technology and auto shut-off safety.",
        image: "static/img/p12.jpg"
    },
    {
        id: 8813,
        name: "Adjustable Aluminum Laptop Stand",
        category: "OFFICE",
        price: 1299,
        rating: 4.7,
        stock: 70,
        description: "Ergonomic foldable aluminum riser supporting laptops up to 17 inches for improved posture.",
        image: "static/img/p13.jpg"
    },
    {
        id: 8814,
        name: "Wooden Desk Organizer & Caddy",
        category: "OFFICE",
        price: 599,
        rating: 4.4,
        stock: 95,
        description: "Multi-compartment natural walnut desk caddy for stationary, pens, and daily accessories.",
        image: "static/img/p14.jpg"
    },
    {
        id: 8815,
        name: "Hardcover Premium Journal Notebook",
        category: "OFFICE",
        price: 299,
        rating: 4.6,
        stock: 150,
        description: "A5 thick dotted grid notebook with expandable inner pocket and bookmark ribbon.",
        image: "static/img/p15.jpg"
    },
    {
        id: 8816,
        name: "Waterproof Laptop Sleeve 15.6 Inch",
        category: "ACCESSORIES",
        price: 899,
        rating: 4.5,
        stock: 75,
        description: "Shockproof padded protective sleeve with accessory pocket for charger and cables.",
        image: "static/img/p16.jpg"
    },
    {
        id: 8817,
        name: "Water-Resistant Travel Backpack",
        category: "TRAVEL",
        price: 1499,
        rating: 4.8,
        stock: 55,
        description: "Spacious 30L commuter backpack with anti-theft back pocket and USB charging port.",
        image: "static/img/p17.jpg"
    },
    {
        id: 8818,
        name: "Lightweight Breathable Running Shoes",
        category: "FASHION & SPORTS",
        price: 2499,
        rating: 4.6,
        stock: 40,
        description: "Cushioned road running sneakers with breathable mesh upper and durable rubber grip.",
        image: "static/img/p18.jpg"
    },
    {
        id: 8819,
        name: "Polarized Classic UV Sunglasses",
        category: "FASHION",
        price: 999,
        rating: 4.4,
        stock: 65,
        description: "Timeless unisex polarized wayfarer sunglasses with 100% UV400 protection.",
        image: "static/img/p19.jpg"
    },
    {
        id: 8820,
        name: "Adjustable Smartphone Desktop Stand",
        category: "ACCESSORIES",
        price: 499,
        rating: 4.5,
        stock: 110,
        description: "Heavy-duty aluminum phone holder with anti-slip silicone pads and multi-angle rotation.",
        image: "static/img/p20.jpg"
    },
    {
        id: 8821,
        name: "Minimalist Wooden Stool",
        category: "FURNITURE",
        price: 1899,
        rating: 4.7,
        stock: 20,
        description: "Solid oak tripod stool suitable for dining counters, study desks, or bedside accent.",
        image: "static/img/p21.jpg"
    },
    {
        id: 8822,
        name: "Ceramic Minimalist Plant Pot",
        category: "HOME & KITCHEN",
        price: 649,
        rating: 4.6,
        stock: 50,
        description: "Modern matte ceramic planter with drainage tray for indoor succulents and foliage.",
        image: "static/img/p22.jpg"
    },
    {
        id: 8823,
        name: "Woven Cotton Throw Blanket",
        category: "HOME & TEXTILES",
        price: 1199,
        rating: 4.7,
        stock: 45,
        description: "Ultra-soft breathable 100% natural cotton throw blanket with tasseled fringe borders.",
        image: "static/img/p23.jpg"
    },
    {
        id: 8824,
        name: "Artisanal Wooden Serving Tray",
        category: "HOME & KITCHEN",
        price: 849,
        rating: 4.5,
        stock: 35,
        description: "Solid teakwood rectangular platter tray with carved handles for breakfast or coffee service.",
        image: "static/img/p24.jpg"
    }
];

function formatPrice(price) {
    return '₹' + Number(price).toLocaleString('en-IN');
}

function makeProduct(id) {
    const index = (id - 8801) % REAL_PRODUCTS.length;
    const base = REAL_PRODUCTS[index];
    return {
        id: id,
        name: base.name,
        category: base.category,
        price: base.price,
        formattedPrice: formatPrice(base.price),
        rating: base.rating,
        stock: base.stock,
        description: base.description,
        gradient: 'linear-gradient(135deg, #f5f5f7, #e5e5ea)',
        image: base.image
    };
}

const PRODUCTS = Array.from({length: 600}, (_, i) => makeProduct(8801 + i));
window.PRODUCTS = PRODUCTS;
window.formatPrice = formatPrice;

function getProductById(id) {
    return PRODUCTS.find(p => p.id === id);
}

function getProductsPage(page, perPage = 12) {
    const start = (page - 1) * perPage;
    return PRODUCTS.slice(start, start + perPage);
}
