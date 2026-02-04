const express = require('express')
const app = express()
const port = 3000
let data = [
    {
        "id": "1",
        "title": "a title",
        "views": 100
    },
    {
        "id": "2",
        "title": "another title",
        "views": 200
    },
    {
        "id": "3",
        "title": "another title",
        "views": 200
    },
    {
        "id": "4",
        "title": "chu tu",
        "views": 900
    },
    {
        "id": "5",
        "title": "to",
        "views": 900
    },
    {
        "id": "6",
        "title": "hahah",
        "views": 999
    },
    {
        "id": "7",
        "title": "arap",
        "views": 999,
        "isDeleted": "true"
    },
    {
        "id": "99",
        "title": "909999",
        "views": 99
    },
    {
        "id": "9999",
        "title": "99",
        "views": 999
    },
    {
        "id": "9999",
        "title": "99",
        "views": 999,
        "isDeleted": true
    }
]
//get all
//title=a&maxview=400&minview=50&limit=4&page=2
app.get('/api/v1/products', (req, res) => {
    let titleQ = req.query.title ? req.query.title : '';
    let maxView = req.query.maxview ? req.query.maxview : 1E6;
    let minView = req.query.minview ? req.query.minview : 0;
    let limit = req.query.limit ? req.query.limit : 5;
    let page = req.query.page ? req.query.page : 1;
    let result = data.filter(
        function (e) {
            return !(e.isDeleted) && e.title.includes(titleQ)
                && e.views >= minView && e.views <= maxView;
        }
    )
    result = result.splice(limit * (page - 1), limit);
    res.send(result)
})
app.get('/api/v1/products/:ids', (req, res) => {
    let id = req.params.ids;
    let result = data.filter(
        function (e) {
            return !(e.isDeleted) && e.id == id
        }
    )
    if (result.length > 0) {
        res.send(result[0])
    } else {
        res.status(404).send({
            message: "ID NOT FOUND"
        })
    }

})
app.get('/api/v1/products/2', (req, res) => {
    res.send('Hello World! 1')
})
app.put('/api/v1/products/1', (req, res) => {
    res.send('Hello World! 1')
})
app.delete('/api/v1/products/1', (req, res) => {
    res.send('Hello World! 1')
})
app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
