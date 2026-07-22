#!/usr/bin/env python3
"""
生成贪吃蛇动态 SVG
"""

import random
import time
from datetime import datetime

# SVG 配置
GRID_SIZE = 20
CELL_SIZE = 20
CANVAS_SIZE = GRID_SIZE * CELL_SIZE
BG_COLOR = "#1f2e38"
SNAKE_HEAD = "#7bed8a"
SNAKE_BODY = "#2e8b57"
FOOD_COLOR = "#ff3b3b"
GRID_COLOR = "#2d4452"

# 动画帧数
FRAMES = 50
MOVE_INTERVAL = 0.15  # 每帧间隔秒

def generate_snake_frames():
    """生成贪吃蛇动画的每一帧"""
    # 初始化蛇
    snake = [[9, 10], [8, 10], [7, 10], [6, 10]]
    direction = 'right'
    next_direction = 'right'
    
    # 生成食物
    food = [12, 10]
    snake_set = set(tuple(p) for p in snake)
    while tuple(food) in snake_set:
        food = [random.randint(0, GRID_SIZE-1), random.randint(0, GRID_SIZE-1)]
    
    frames = []
    score = 0
    game_over = False
    
    for _ in range(FRAMES):
        if game_over:
            # 游戏结束，重复最后一帧
            frames.append({
                'snake': snake,
                'food': food,
                'score': score,
                'game_over': True
            })
            continue
        
        # 更新方向
        if next_direction:
            opposite = {'up': 'down', 'down': 'up', 'left': 'right', 'right': 'left'}
            if opposite.get(next_direction) != direction:
                direction = next_direction
        
        # 计算新头部
        head = snake[0]
        new_head = head.copy()
        if direction == 'right':
            new_head[0] += 1
        elif direction == 'left':
            new_head[0] -= 1
        elif direction == 'up':
            new_head[1] -= 1
        elif direction == 'down':
            new_head[1] += 1
        
        # 检测是否吃到食物
        is_eating = (new_head[0] == food[0] and new_head[1] == food[1])
        
        # 构建新蛇
        new_snake = [new_head]
        end_index = len(snake) - (1 if is_eating else 0)
        for i in range(end_index):
            new_snake.append(snake[i])
        
        # 碰撞检测
        head_str = f"{new_head[0]},{new_head[1]}"
        wall_collision = (new_head[0] < 0 or new_head[0] >= GRID_SIZE or 
                         new_head[1] < 0 or new_head[1] >= GRID_SIZE)
        
        self_collision = False
        for i in range(1, len(new_snake)):
            if f"{new_snake[i][0]},{new_snake[i][1]}" == head_str:
                self_collision = True
                break
        
        if wall_collision or self_collision:
            game_over = True
            frames.append({
                'snake': new_snake,
                'food': food,
                'score': score,
                'game_over': True
            })
            continue
        
        snake = new_snake
        
        # 处理吃到食物
        if is_eating:
            score += 1
            # 生成新食物
            snake_set = set(tuple(p) for p in snake)
            if len(snake_set) >= GRID_SIZE * GRID_SIZE:
                game_over = True
                frames.append({
                    'snake': snake,
                    'food': food,
                    'score': score,
                    'game_over': True
                })
                continue
            new_food = None
            attempts = 0
            while attempts < 100:
                fx = random.randint(0, GRID_SIZE-1)
                fy = random.randint(0, GRID_SIZE-1)
                if (fx, fy) not in snake_set:
                    new_food = [fx, fy]
                    break
                attempts += 1
            if new_food:
                food = new_food
            else:
                # 理论上不可能，兜底
                for y in range(GRID_SIZE):
                    for x in range(GRID_SIZE):
                        if (x, y) not in snake_set:
                            food = [x, y]
                            break
                    if food:
                        break
        
        frames.append({
            'snake': snake,
            'food': food,
            'score': score,
            'game_over': False
        })
    
    return frames

def render_svg(frames, output_path="snake.svg"):
    """将帧序列渲染为 SVG 动画"""
    svg_parts = []
    
    # SVG 头部
    svg_parts.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" 
     width="{CANVAS_SIZE}" height="{CANVAS_SIZE + 60}" 
     viewBox="0 0 {CANVAS_SIZE} {CANVAS_SIZE + 60}"
     style="background: {BG_COLOR}; font-family: 'Segoe UI', sans-serif;">
     
    <defs>
        <style>
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.5; }}
            }}
            .food {{ animation: pulse 0.8s ease-in-out infinite; }}
        </style>
    </defs>
    
    <!-- 网格线 -->
    <g stroke="{GRID_COLOR}" stroke-width="0.5" opacity="0.3">
''')
    
    # 网格线
    for i in range(GRID_SIZE + 1):
        svg_parts.append(f'        <line x1="{i*CELL_SIZE}" y1="0" x2="{i*CELL_SIZE}" y2="{CANVAS_SIZE}"/>')
        svg_parts.append(f'        <line x1="0" y1="{i*CELL_SIZE}" x2="{CANVAS_SIZE}" y2="{i*CELL_SIZE}"/>')
    
    svg_parts.append('    </g>\n')
    
    # 动画帧
    for idx, frame in enumerate(frames):
        # 如果是最后一帧，显示"游戏结束"
        is_last = (idx == len(frames) - 1)
        
        # 可见性控制
        begin_time = idx * MOVE_INTERVAL
        end_time = (idx + 1) * MOVE_INTERVAL if not is_last else "indefinite"
        
        visibility = f'<set attributeName="visibility" to="visible" begin="{begin_time}s" end="{end_time}s"/>'
        
        # 食物
        if not frame['game_over'] or is_last:
            fx, fy = frame['food']
            cx = fx * CELL_SIZE + CELL_SIZE / 2
            cy = fy * CELL_SIZE + CELL_SIZE / 2
            radius = CELL_SIZE * 0.35
            
            svg_parts.append(f'''
    <!-- 帧 {idx} - 食物 -->
    <g visibility="hidden">
        {visibility}
        <circle cx="{cx}" cy="{cy}" r="{radius}" fill="{FOOD_COLOR}" class="food"/>
        <circle cx="{cx-2}" cy="{cy-3}" r="{radius*0.3}" fill="#ff8a8a" opacity="0.7"/>
    </g>''')
        
        # 蛇
        snake = frame['snake']
        for i, (sx, sy) in enumerate(snake):
            is_head = (i == 0)
            x = sx * CELL_SIZE
            y = sy * CELL_SIZE
            size = CELL_SIZE - 2
            
            if is_head:
                color = SNAKE_HEAD
            else:
                # 渐变色
                ratio = i / len(snake) if len(snake) > 0 else 0
                green = int(70 + 100 * (1 - ratio))
                color = f"rgb(30, {green}, 70)"
            
            svg_parts.append(f'''
    <!-- 帧 {idx} - 蛇节 {i} -->
    <g visibility="hidden">
        {visibility}
        <rect x="{x+1}" y="{y+1}" width="{size}" height="{size}" rx="3" 
              fill="{color}" stroke="none"/>
''')
            
            # 蛇头眼睛
            if is_head:
                # 根据方向调整眼睛位置
                eye_x1, eye_y1, eye_x2, eye_y2 = 0, 0, 0, 0
                if direction == 'right':
                    eye_x1, eye_y1 = x + 10, y + 4
                    eye_x2, eye_y2 = x + 10, y + 12
                elif direction == 'left':
                    eye_x1, eye_y1 = x + 6, y + 4
                    eye_x2, eye_y2 = x + 6, y + 12
                elif direction == 'up':
                    eye_x1, eye_y1 = x + 4, y + 6
                    eye_x2, eye_y2 = x + 12, y + 6
                else:  # down
                    eye_x1, eye_y1 = x + 4, y + 10
                    eye_x2, eye_y2 = x + 12, y + 10
                
                svg_parts.append(f'''
        <circle cx="{eye_x1}" cy="{eye_y1}" r="2" fill="#f0faf4"/>
        <circle cx="{eye_x2}" cy="{eye_y2}" r="2" fill="#f0faf4"/>
        <circle cx="{eye_x1+1}" cy="{eye_y1}" r="1" fill="#0a1a1a"/>
        <circle cx="{eye_x2+1}" cy="{eye_y2}" r="1" fill="#0a1a1a"/>
''')
            
            svg_parts.append('    </g>')
    
    # 显示分数（动画结束后显示最终分数）
    final_score = frames[-1]['score'] if frames else 0
    svg_parts.append(f'''
    <!-- 分数 -->
    <g>
        <rect x="0" y="{CANVAS_SIZE}" width="{CANVAS_SIZE}" height="60" fill="{BG_COLOR}" opacity="0.9"/>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE + 35}" 
              text-anchor="middle" fill="#b7e4d4" font-size="20" font-weight="bold">
            🍎 分数: <tspan fill="#f5c542">{final_score}</tspan>
        </text>
    </g>
''')
    
    # 游戏结束标记
    last_frame = frames[-1] if frames else None
    if last_frame and last_frame['game_over']:
        svg_parts.append(f'''
    <!-- 游戏结束蒙层 -->
    <g>
        <rect x="0" y="0" width="{CANVAS_SIZE}" height="{CANVAS_SIZE}" 
              fill="rgba(8,18,24,0.75)" visibility="hidden">
            <animate attributeName="visibility" to="visible" 
                     begin="{len(frames)*MOVE_INTERVAL}s" dur="1s" fill="freeze"/>
        </rect>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE/2 - 10}" 
              text-anchor="middle" fill="#f28b82" font-size="32" font-weight="bold"
              visibility="hidden">
            💀 游戏结束
            <animate attributeName="visibility" to="visible" 
                     begin="{len(frames)*MOVE_INTERVAL}s" dur="1s" fill="freeze"/>
        </text>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE/2 + 30}" 
              text-anchor="middle" fill="#bdd9d0" font-size="14"
              visibility="hidden">
            刷新页面重新观看
            <animate attributeName="visibility" to="visible" 
                     begin="{len(frames)*MOVE_INTERVAL}s" dur="1s" fill="freeze"/>
        </text>
    </g>
''')
    
    svg_parts.append('\n</svg>')
    
    # 写入文件
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(''.join(svg_parts))
    
    print(f"✅ SVG 已生成: {output_path}")
    print(f"📊 总帧数: {len(frames)}")
    print(f"🏆 最终分数: {final_score}")
    print(f"⏱️  动画时长: {len(frames) * MOVE_INTERVAL:.1f} 秒")

if __name__ == "__main__":
    # 设置随机种子以保证可重现性（可选）
    random.seed(int(time.time()))
    
    # 生成动画帧
    print("🎮 生成贪吃蛇动画帧...")
    frames = generate_snake_frames()
    
    # 渲染 SVG
    render_svg(frames, "snake.svg")
