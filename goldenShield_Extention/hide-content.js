const BLOCKED_DOMAINS_GAMBLING = [
    "bingoplus.ph", "bingoplus.com", "bingoplus.net", "lucky.bingoplus.com", "fun.bingoplus.com", "play.bingoplus.com",
    "bingoplus.com.ph", "bingoplus.online", "bingoplusios1.com", "bingoplusios2.com", "bingoplusandroid1.com", "bingoplusandroid2.com",
    "fishplus.ph", "minesplus.ph", "blingwin.com", "happybingo.ph", "crazywin.ph", "747ph.live", "747.live", "gameph.com",
    "nustarmax.com", "patokbet.com", "pagcor.ph", "happyplay.ph", "gamefun.ph", "wwwgamefun.ph", "bp-poker.com", "bppoker.ph",
    "bppoker.net", "bppoker.live", "bppoker.app", "okbet.com", "okgames.com", "okgames.net", "ok-games.ph", "okapp.chat",
    "okbet.game", "okbet.help", "okbet.link", "okbet.net", "okbet.one", "okfun.ph", "okplay.ph", "okgames.ph",
    "hawkgaming.com", "s5.com", "ggpoker.ph", "filbet.com", "ps88.com", "pisogame.com", "pesogame.com", "buenas.ph",
    "inplay.ph", "igo.ph", "sportsplus.ph", "sportsplus.com.ph", "jadesportsbet.com", "sportsmaxx.ph", "fastwin.ph",
    "bethub.ph", "bethub.com.ph", "gamexsports.com", "gamexsports.ph", "gamexports.com.ph", "legendlink.com", "fbmemotion.ph",
    "fairplay.ph", "fairplay.com.ph", "ArionPlay.com", "bigwin29.com", "msw.ph", "egamescasino.ph", "playtime.ph",
    "playtime.com.ph", "spintime.ph", "cardtime.ph", "sulobet.ph", "LakiWin.com", "LakiPlay.com", "lets.playdailyfantasy.com",
    "deskgame.com", "deskgame.vip", "deskgame.org", "deskgame.co", "deskgame.club", "deskgame.me", "winzir.ph", "winzir.com",
    "winzir.net", "winzir.com.ph", "sg8.casino", "sg8.zone", "sg8.bet", "festival.sg8.casino", "bsports.ph", "arenaplus.ph",
    "arenaplus.net", "arenaplusvip.ph", "arenaplusvip.net", "arenaplusvip.com", "arena-plus.online", "arenaplusios1.com",
    "arenaplusios2.com", "arenaplusandroid1.com", "arenaplusandroid2.com", "arenaplus.asia", "arenaplus.info", "arenaplus.life",
    "arenaplus.org", "arenaplus.pro", "arenaplus.site", "arenaplus.today", "arenaplus.world", "arenapro.xyz", "arenaplus.fun",
    "gamezone88.com", "gamezone.ph", "gamezonebet.com", "peryagame.com", "peryagame.net", "peryagame.ph", "colorgameplus.com",
    "tripledg.com", "tripledg1.com", "tripledg2.com", "bet88.ph", "goplayasia.com", "king.ph", "lucky.ph", "queen.ph", "bosscat.ph",
    "hqhole.com", "hdsexdino.com", "pornbigvideo.com", "sweetshow.com", "mylust.com", "sleazyneasy.com", "sexpulse.tv",
    "sexmole.com", "spankbang.com", "freeadultmedia.com", "bangbrosteenporn.com", "porn8.com", "collectionofbestporn.com",
    "hqporner.com", "freeviewmovies.com", "youporn.com", "pornhub.com", "adultfriendfinder.com", "adultfriendfinders.com",
    "adultfriendfinderz.com", "adultfriendsearch.com", "adultbanners.co.uk", "adultcash.com", "adultdatingtraffic.com",
    "adultmoneymakers.com", "adultpopunders.com", "adultrevenueservice.com", "adulttrafficads.com", "adultvalleycash.com",
    "adultwebmastersonline.com", "adultlinkexchange.com", "adultlinksco.com", "adultmoda.com", "adultadworld.com"
];

const BLOCKED_URLS = [];

let blockedUrls = BLOCKED_URLS;
const tags = "SPANEMBIULOLI";
let total = 0;

// Function to hide content based on blocked URLs
function hideContentBasedOnUrls() {
    const currentUrl = window.location.href;
    for (let ii = 0; ii < BLOCKED_URLS.length; ii++) {
        const blockedUrl = BLOCKED_URLS[ii];
        if (currentUrl.includes(blockedUrl)) {
            const body = document.body;
            body.innerHTML = '[TEXT BLOCKED: ADULT CONTENT DETECTED]';
            body.style.color = 'red';
            return;
        }
    }
    hideContentBasedOnKeywords();
}

// Function to hide content based on keywords
function hideContentBasedOnKeywords() {
    for (let ii = 0; ii < kw.length; ii++) {
        const o = $(`:contains(${kw[ii]}):not(:has(:contains(${kw[ii]})))`);
        for (let i = 0; i < o.length; i++) {
            if (!o[i].parentNode || o[i].parentNode.nodeName === "BODY") continue;
            hideSpoiler(o[i]);
            total++;
        }
    }

    // Hide headings if total matches or exceeds 10
    if (total >= 10) {
        const headings = document.querySelectorAll("h1, h2, h3, h4, h5, h6, p");
        for (let i = 0; i < headings.length; i++) hideNode(headings[i]);
    }
}

// Function to hide spoilers
function hideSpoiler(node) {
    let ancestor = node.parentNode;
    if (ancestor != null) {
        if (ancestor.parentNode != null && ancestor.tagName != 'BODY') {
            ancestor = ancestor.parentNode;
        }
        const imgs = ancestor.getElementsByTagName('img');
        for (let i = 0; i < imgs.length; i++) {
            imgs[i].style.webkitFilter = "blur(20px)";
        }
        const lists = ancestor.getElementsByTagName('li');
        for (let i = 0; i < lists.length; i++) hideNode(lists[i]);
    }

    if (node == null || node.parentNode == null) return;
    const all_child = node.parentNode.children;
    for (let i = 0; i < all_child.length; i++) {
        const type = all_child[i].tagName;
        if (tags.match(type) != null) hideNode(all_child[i]);
    }
    hideNode(node);
}

// Function to hide nodes
function hideNode(node) {
    node.textContent = '[TEXT BLOCKED: ADULT OR GAMBLING CONTENT DETECTED]';
    node.style.color = 'red';
}

// Function to check if the current domain is in the blocked gambling domains
function isGamblingDomain() {
    const currentDomain = window.location.hostname;
    return BLOCKED_DOMAINS_GAMBLING.includes(currentDomain);
}

// Hide content if the current domain is a gambling site
// Execute blocking logic
if (isGamblingDomain()) {
    const body = document.body;
    body.innerHTML = '[TEXT BLOCKED: ADULT OR GAMBLING CONTENT DETECTED]';
    body.style.color = 'red';
} else {
    hideContentBasedOnUrls();
}
