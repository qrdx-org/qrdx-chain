# QRDX Testing Dashboards

This directory contains pure HTML testing dashboards for monitoring and visualizing the QRDX blockchain network. All dashboards are self-contained HTML files that can be opened directly in a browser.

## 🚀 Quick Start

1. Make sure your testnet is running:
   ```bash
   bash scripts/testnet.sh start
   ```

2. Open any dashboard in your browser:
   ```bash
   # Using default browser
   xdg-open testnet/dashboard.html
   
   # Or use the BROWSER environment variable
   $BROWSER testnet/dashboard.html
   ```

## 📊 Available Dashboards

### 1. Network Dashboard (`dashboard.html`)
**Focus**: Real-time network topology and blockchain stats

**Features**:
- 🌐 **Interactive Node Bubble Map** - Visual representation of network topology with animated connections
- 📊 **Live Statistics** - Block height, active nodes, pending transactions, difficulty
- 📦 **Recent Blocks** - Latest blocks with transaction counts and timestamps
- 💰 **Recent Transactions** - Live transaction feed with amounts and status
- 🔄 **Auto-refresh** - Updates every 5 seconds

**Best for**: Understanding network structure and overall health

### 2. Mining Dashboard (`mining-dashboard.html`)
**Focus**: Mining operations and network hashrate

**Features**:
- ⚡ **Network Hashrate** - Current, average, and peak hashrate metrics
- 🎯 **Difficulty Tracking** - Current difficulty and adjustment predictions
- 💰 **Block Rewards** - Current reward and halving countdown
- 📈 **Difficulty History Chart** - Visual chart of last 20 blocks
- 🔨 **Recent Blocks Mined** - Table of latest mined blocks
- 🎲 **Mining Candidates** - Mempool status and merkle root
- ⏱️ **Next Block Countdown** - Real-time estimate with progress bar

**Best for**: Miners and network difficulty monitoring

### 3. Blockchain Explorer (`explorer.html`)
**Focus**: Blockchain data exploration and search

**Features**:
- 🔍 **Search Functionality** - Search blocks, transactions, and addresses
- 📊 **Chain Statistics** - Height, total blocks, total TXs, network hash
- 📦 **Block Timeline** - Detailed block cards with all metadata
- 💳 **Transaction Table** - Sortable transaction history
- 🌐 **Network Status** - Node count, version, mempool size
- 🎨 **Beautiful UI** - Modern gradient design with smooth animations

**Best for**: Exploring blockchain data and searching for specific items

### 4. Validator Dashboard (`validator-dashboard.html`)
**Focus**: Proof-of-Stake validator monitoring

**Features**:
- 🛡️ **Validator List** - All active validators with stakes and performance
- 📊 **Stake Distribution** - Visual representation of stake across validators
- ⏰ **Epoch Progress** - Current epoch status with slot countdown
- ✅ **Attestation Grid** - Visual history of last 100 attestations
- 💎 **Rewards Chart** - Validator rewards over last 10 epochs
- 📈 **Network APY** - Staking yield and metrics
- 🎯 **Validator Performance** - Effectiveness, uptime, and block proposals

**Best for**: Validators and staking participants

## 🔗 API Endpoints Used

All dashboards connect to local testnet nodes:
- Node 0: `http://127.0.0.1:3007`
- Node 1: `http://127.0.0.1:3008`
- Node 2: `http://127.0.0.1:3009`
- Node 3: `http://127.0.0.1:3010`

### Common Endpoints
- `GET /` - Node version and basic info
- `GET /get_status` - Current block height and status
- `GET /get_blocks?offset=0&limit=10` - Recent blocks
- `GET /get_mining_info` - Mining template and difficulty
- `POST /get_peers` - Connected peers (requires authentication)

## 🎨 Dashboard Features

### Common Features Across All Dashboards
- ✨ **Pure HTML/CSS/JavaScript** - No build tools required
- 🔄 **Auto-refresh** - Live data updates
- 📱 **Responsive Design** - Works on desktop and mobile
- 🎭 **Beautiful Animations** - Smooth transitions and effects
- 🌐 **Cross-browser Compatible** - Works in all modern browsers
- 💾 **No Backend Required** - Direct API calls to nodes

### Visual Design Themes
1. **Network Dashboard**: Cyberpunk blue/cyan theme with glowing effects
2. **Mining Dashboard**: Terminal green/black hacker aesthetic
3. **Blockchain Explorer**: Modern purple gradient with clean cards
4. **Validator Dashboard**: Professional dark blue with elegant UI

## 🛠️ Customization

### Change API Endpoints
Edit the `NODES` array in each HTML file:

```javascript
const NODES = [
    { url: 'http://your-node:port', name: 'Node 0' },
    // Add more nodes...
];
```

### Adjust Refresh Rate
Modify the `setInterval` calls:

```javascript
// Change from 5000ms (5 seconds) to desired interval
setInterval(refreshAll, 5000);
```

### Color Themes
Each dashboard has CSS variables at the top of the `<style>` section for easy theme customization.

## 📊 Mock Data vs Real Data

Currently, these dashboards use a mix of:
- ✅ **Real data**: Node version, basic node status
- 🎲 **Mock data**: Detailed blockchain stats, transactions, validators

To connect real data:
1. Implement the missing RPC endpoints in the node (see RPC module docs)
2. Update the fetch functions in each dashboard to use real endpoints
3. Adjust data parsing to match actual API responses

## 🐛 Troubleshooting

### Dashboard shows "Loading..."
- Ensure testnet is running: `bash scripts/testnet.sh status`
- Check node accessibility: `curl http://127.0.0.1:3007/`
- Look for CORS errors in browser console

### No network visualization
- Refresh the page
- Check browser console for JavaScript errors
- Ensure browser supports Canvas API

### Data not updating
- Check browser console for fetch errors
- Verify nodes are responding: `curl http://127.0.0.1:3007/`
- Try manual refresh button

## 🔮 Future Enhancements

Planned improvements:
- [ ] Real-time WebSocket connections for instant updates
- [ ] Historical data charts with time range selection
- [ ] Transaction detail modal views
- [ ] Address portfolio tracking
- [ ] Validator registration interface
- [ ] Network health scoring
- [ ] Export data to CSV/JSON
- [ ] Dark/light theme toggle
- [ ] Multi-language support
- [ ] Mobile app wrapper

## 📝 Development Notes

### Adding New Visualizations

1. Create new HTML file in `testnet/` directory
2. Follow existing structure:
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <style>/* Your styles */</style>
   </head>
   <body>
       <!-- Your content -->
       <script>/* Your logic */</script>
   </body>
   </html>
   ```

3. Connect to node APIs
4. Add auto-refresh logic
5. Document in this README

### Best Practices

- Keep dashboards as single HTML files for portability
- Use modern JavaScript (ES6+) features
- Implement graceful error handling
- Add loading states for better UX
- Use CSS animations for smooth transitions
- Make responsive for all screen sizes

## 📚 Resources

- [QRDX Documentation](../docs/)
- [RPC API Reference](../docs/RPC_API.md)
- [Testnet Setup Guide](../scripts/TESTNET.md)
- [Node Configuration](../config.example.toml)

## 🤝 Contributing

To contribute new dashboards or improvements:

1. Create your dashboard HTML file
2. Test with local testnet
3. Document features in this README
4. Submit PR with screenshots

## 📄 License

These dashboards are part of the QRDX project and follow the same license (AGPLv3).

---

**Made with ❤️ for the QRDX Community**
