const REAL_PRODUCTS = [
    {
        id: 8801,
        name: "Wireless Bluetooth Headphones",
        category: "ELECTRONICS",
        price: 2499,
        rating: 4.7,
        stock: 45,
        description: "High-fidelity wireless over-ear headphones with active noise cancellation and 30-hour battery life.",
        image: "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8802,
        name: "Mechanical Gaming Keyboard",
        category: "ELECTRONICS",
        price: 3299,
        rating: 4.8,
        stock: 30,
        description: "RGB tactile mechanical keyboard with custom hot-swappable switches and ergonomic wrist rest.",
        image: "https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8803,
        name: "Ergonomic Wireless Mouse",
        category: "ELECTRONICS",
        price: 699,
        rating: 4.5,
        stock: 80,
        description: "Precision 2.4GHz wireless optical mouse with ergonomic grip and silent click switches.",
        image: "https://images.unsplash.com/photo-1615663245857-ac93bb7c39e7?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8804,
        name: "Wireless Noise-Canceling Earbuds",
        category: "ELECTRONICS",
        price: 1799,
        rating: 4.6,
        stock: 65,
        description: "Compact true wireless earbuds with deep bass, IPX5 water resistance, and wireless charging case.",
        image: "https://images.unsplash.com/photo-1590658268037-6bf12165a8df?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8805,
        name: "Portable Bluetooth Speaker",
        category: "ELECTRONICS",
        price: 1599,
        rating: 4.4,
        stock: 50,
        description: "Rugged waterproof portable speaker with 360-degree room-filling sound and 12-hour playtime.",
        image: "https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8806,
        name: "20,000mAh Fast Charging Power Bank",
        category: "ELECTRONICS",
        price: 1299,
        rating: 4.7,
        stock: 90,
        description: "High-capacity power bank with 22.5W fast charging support and dual USB-C/USB-A output ports.",
        image: "https://images.unsplash.com/photo-1609592424074-13c548a851d9?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8807,
        name: "Smartwatch with Fitness Tracker",
        category: "ELECTRONICS",
        price: 2999,
        rating: 4.5,
        stock: 40,
        description: "Feature-rich smartwatch with heart rate monitor, SpO2 sensor, sleep tracking, and AMOLED display.",
        image: "https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8808,
        name: "External 1TB Portable SSD",
        category: "ELECTRONICS",
        price: 5999,
        rating: 4.9,
        stock: 25,
        description: "Ultra-fast 1050MB/s USB 3.2 Gen 2 portable solid-state drive with shock-resistant aluminum casing.",
        image: "https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8809,
        name: "Smart LED Desk Lamp",
        category: "HOME & OFFICE",
        price: 1099,
        rating: 4.6,
        stock: 60,
        description: "Dimmable LED desk lamp with touch control, adjustable color temperature, and built-in USB charger.",
        image: "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8810,
        name: "Stainless Steel Water Bottle",
        category: "HOME & KITCHEN",
        price: 799,
        rating: 4.8,
        stock: 120,
        description: "Double-wall vacuum insulated flask keeping drinks cold for 24 hours or hot for 12 hours.",
        image: "https://images.unsplash.com/photo-1602143407151-7111542de6e8?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8811,
        name: "Ceramic Artisan Coffee Mug",
        category: "HOME & KITCHEN",
        price: 399,
        rating: 4.5,
        stock: 85,
        description: "Handcrafted 350ml ceramic coffee mug with comfortable handle and smooth matte glaze finish.",
        image: "https://images.unsplash.com/photo-1514432324607-a09d9b4aefdd?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8812,
        name: "Electric Gooseneck Water Kettle",
        category: "HOME & KITCHEN",
        price: 2199,
        rating: 4.7,
        stock: 35,
        description: "Precision pour-over electric kettle with rapid boiling technology and auto shut-off safety.",
        image: "https://images.unsplash.com/photo-1544787219-7f47ccb76574?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8813,
        name: "Adjustable Aluminum Laptop Stand",
        category: "OFFICE",
        price: 1299,
        rating: 4.7,
        stock: 70,
        description: "Ergonomic foldable aluminum riser supporting laptops up to 17 inches for improved posture.",
        image: "https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8814,
        name: "Wooden Desk Organizer & Caddy",
        category: "OFFICE",
        price: 599,
        rating: 4.4,
        stock: 95,
        description: "Multi-compartment natural walnut desk caddy for stationary, pens, and daily accessories.",
        image: "https://images.unsplash.com/photo-1544816155-12df9643f363?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8815,
        name: "Hardcover Premium Journal Notebook",
        category: "OFFICE",
        price: 299,
        rating: 4.6,
        stock: 150,
        description: "A5 thick dotted grid notebook with expandable inner pocket and bookmark ribbon.",
        image: "https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8816,
        name: "Waterproof Laptop Sleeve 15.6 Inch",
        category: "ACCESSORIES",
        price: 899,
        rating: 4.5,
        stock: 75,
        description: "Shockproof padded protective sleeve with accessory pocket for charger and cables.",
        image: "https://images.unsplash.com/photo-1588872657578-7efd1f1555ed?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8817,
        name: "Water-Resistant Travel Backpack",
        category: "TRAVEL",
        price: 1499,
        rating: 4.8,
        stock: 55,
        description: "Spacious 30L commuter backpack with anti-theft back pocket and USB charging port.",
        image: "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8818,
        name: "Lightweight Breathable Running Shoes",
        category: "FASHION & SPORTS",
        price: 2499,
        rating: 4.6,
        stock: 40,
        description: "Cushioned road running sneakers with breathable mesh upper and durable rubber grip.",
        image: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8819,
        name: "Polarized Classic UV Sunglasses",
        category: "FASHION",
        price: 999,
        rating: 4.4,
        stock: 65,
        description: "Timeless unisex polarized wayfarer sunglasses with 100% UV400 protection.",
        image: "https://images.unsplash.com/photo-1511499767150-a48a237f0083?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8820,
        name: "Adjustable Smartphone Desktop Stand",
        category: "ACCESSORIES",
        price: 499,
        rating: 4.5,
        stock: 110,
        description: "Heavy-duty aluminum phone holder with anti-slip silicone pads and multi-angle rotation.",
        image: "https://images.unsplash.com/photo-1586105251261-72a756497a11?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8821,
        name: "Minimalist Wooden Stool",
        category: "FURNITURE",
        price: 1899,
        rating: 4.7,
        stock: 20,
        description: "Solid oak tripod stool suitable for dining counters, study desks, or bedside accent.",
        image: "https://images.unsplash.com/photo-1503602642458-232111445657?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8822,
        name: "Ceramic Minimalist Plant Pot",
        category: "HOME & KITCHEN",
        price: 649,
        rating: 4.6,
        stock: 50,
        description: "Modern matte ceramic planter with drainage tray for indoor succulents and foliage.",
        image: "https://images.unsplash.com/photo-1485955900006-10f4d324d411?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8823,
        name: "Woven Cotton Throw Blanket",
        category: "HOME & TEXTILES",
        price: 1199,
        rating: 4.7,
        stock: 45,
        description: "Ultra-soft breathable 100% natural cotton throw blanket with tasseled fringe borders.",
        image: "https://images.unsplash.com/photo-1584100936595-c0654b55a2e2?auto=format&fit=crop&w=800&q=80"
    },
    {
        id: 8824,
        name: "Artisanal Wooden Serving Tray",
        category: "HOME & KITCHEN",
        price: 849,
        rating: 4.5,
        stock: 35,
        description: "Solid teakwood rectangular platter tray with carved handles for breakfast or coffee service.",
        image: "https://images.unsplash.com/photo-1530018607912-eff2daa1bac4?auto=format&fit=crop&w=800&q=80"
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
