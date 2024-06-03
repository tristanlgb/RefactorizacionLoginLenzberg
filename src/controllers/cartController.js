const Cart = require('../models/Cart');

exports.addProductToCart = async (req, res) => {
    try {
        const { cid, pid } = req.params;
        const { quantity } = req.body;

        const cart = await Cart.findById(cid);
        const productIndex = cart.products.findIndex(p => p.product.toString() === pid);

        if (productIndex !== -1) {
            cart.products[productIndex].quantity += quantity;
        } else {
            cart.products.push({ product: pid, quantity });
        }

        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};

exports.removeProductFromCart = async (req, res) => {
    try {
        const { cid, pid } = req.params;

        const cart = await Cart.findById(cid);
        cart.products = cart.products.filter(p => p.product.toString() !== pid);

        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};

exports.updateProductQuantity = async (req, res) => {
    try {
        const { cid, pid } = req.params;
        const { quantity } = req.body;

        const cart = await Cart.findById(cid);
        const productIndex = cart.products.findIndex(p => p.product.toString() === pid);

        if (productIndex !== -1) {
            cart.products[productIndex].quantity = quantity;
            await cart.save();
            res.json({ status: 'success', payload: cart });
        } else {
            res.status(404).json({ status: 'error', message: 'Product not found in cart' });
        }
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};

exports.clearCart = async (req, res) => {
    try {
        const { cid } = req.params;

        const cart = await Cart.findById(cid);
        cart.products = [];
        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};