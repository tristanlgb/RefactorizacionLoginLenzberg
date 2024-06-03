const Product = require('../models/Product');

exports.getProducts = async (req, res) => {
    try {
        const { limit = 10, page = 1, sort, query } = req.query;
        const skip = (page - 1) * limit;
        const sortOrder = sort === 'asc' ? 1 : -1;

        const filter = query ? { category: query } : {};

        const products = await Product.find(filter)
            .sort(sort ? { price: sortOrder } : {})
            .skip(skip)
            .limit(Number(limit));

        const total = await Product.countDocuments(filter);
        const totalPages = Math.ceil(total / limit);

        res.json({
            status: 'success',
            payload: products,
            totalPages,
            prevPage: page > 1 ? page - 1 : null,
            nextPage: page < totalPages ? page + 1 : null,
            page: Number(page),
            hasPrevPage: page > 1,
            hasNextPage: page < totalPages,
            prevLink: page > 1 ? `/products?limit=${limit}&page=${page - 1}&sort=${sort}&query=${query}` : null,
            nextLink: page < totalPages ? `/products?limit=${limit}&page=${page + 1}&sort=${sort}&query=${query}` : null
        });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};